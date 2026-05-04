# SPDX-License-Identifier: MIT
"""High-level Handshake client — `Handshake`, `HandshakeContext`.

This is the surface most application code touches. A producer constructs ONE
`Handshake` per process, hands it to framework wrappers (Anthropic, OpenAI
Agents, LangGraph, …), and the wrappers call `delegate()` / `handshake()` /
`record_receipt()` under the hood.

Wire flow per agent action::

      hs = Handshake(registry_url=..., kms=SoftwareKMS.generate(did="did:hsk:agent"))

      token = hs.delegate(                       # 1. user → agent
          sub="did:hsk:agent",
          aud="did:hsk:tool.search",
          capability=Capability(name="web.search"),
      )

      ctx = hs.handshake(                        # 2. agent → tool
          aud="did:hsk:tool.search",
          capability=Capability(name="web.search"),
          delegation_chain=[token],
      )

      result = run_the_tool(ctx)                 # 3. real work
      receipt = hs.record_receipt(               # 4. publish receipt
          ctx,
          action="web.search",
          result="ok",
          result_payload={"hits": 3},
      )

The Receipt envelope produced is byte-identical to one produced by the Phase-3
demo signing path — the SDK is the canonical producer, the demo is preserved
for comparison.

Architecture: ADR-0012 (`docs/decisions/0012-framework-wrapper-boundary.md`).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from . import canonicalize
from .kms import KeyManagementProvider, KmsError
from .models import (
    Capability,
    DelegationToken,
    HandshakeRequest,
    HashAlgorithm,
    HashValue,
    Receipt,
    ReceiptResult,
    SignatureAlgorithm,
)

# Spec version pinned by handshake-py; matches Phase-3 Registry's accepted
# `version` field on every envelope. Bumping this MUST be coordinated with the
# canonical Rust core and the Registry's pydantic model.
SPEC_VERSION = "0.2.4"

# Crockford base32 alphabet for ULID-style ids. Matches the regex enforced by
# the spec models in `models.py` (`^(rc|hs|dt)_[0-9A-HJKMNP-TV-Z]{26}$`).
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _b64u(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    pad = (-len(s)) % 4
    return urlsafe_b64decode(s + ("=" * pad))


def _ulid(prefix: str) -> str:
    """Crockford-base32 ULID-ish id sufficient for the spec regex.

    Matches the helper in examples/phase3_demo.py; duplicated here so the SDK
    does not import from examples (which is pkg-noise the wrong direction).
    """

    raw = secrets.token_bytes(16)
    digits: list[str] = []
    n = int.from_bytes(raw, "big")
    for _ in range(26):
        digits.append(_CROCKFORD[n & 0x1F])
        n >>= 5
    return f"{prefix}_{''.join(reversed(digits))}"


def _now_iso(offset_s: int = 0) -> str:
    """RFC3339 UTC with second precision — what the spec models accept."""

    dt = datetime.now(timezone.utc) + timedelta(seconds=offset_s)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _http_post_json(
    url: str,
    body: dict[str, Any],
    *,
    timeout_s: float = 10.0,
    headers: Optional[dict[str, str]] = None,
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode()
    req = Request(url, data=data, method="POST")
    req.add_header("content-type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urlopen(req, timeout=timeout_s) as resp:
            payload = resp.read() or b"{}"
            return resp.status, json.loads(payload)
    except HTTPError as exc:
        body_bytes = exc.read() or b"{}"
        try:
            return exc.code, json.loads(body_bytes)
        except json.JSONDecodeError:
            return exc.code, {"raw": body_bytes.decode("utf-8", errors="replace")}


def _http_get_json(
    url: str, *, timeout_s: float = 10.0
) -> tuple[int, dict[str, Any]]:
    req = Request(url, method="GET")
    try:
        with urlopen(req, timeout=timeout_s) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _hash_payload(payload: Any) -> HashValue:
    """Compute the spec-mandated `result_hash` over a JCS-canonicalized payload.

    Anything Receipt.result_hash points at MUST be reproducible by a third
    party from the receipt body alone — so we canonicalize once here and
    publish the digest. Callers can keep the raw payload off-ledger; the
    digest is the verifiable handle.
    """

    canon = canonicalize(payload)
    return HashValue(alg=HashAlgorithm.SHA_256, value=hashlib.sha256(canon).hexdigest())


@dataclass
class HandshakeContext:
    """Carries a signed `HandshakeRequest` plus the provenance needed to emit
    a matching Receipt.

    The `Handshake` client returns one of these from `handshake()`. Wrappers
    pass it back into `record_receipt()` to publish the result; the
    `handshake_id` field links request → receipt in the Registry's DAG.

    `parent_receipt_ids` tracks upstream receipts whose result this context
    consumes — populated by framework wrappers that bridge multiple agents
    (the cross-framework DAG demo). When `record_receipt()` runs it copies
    these into `Receipt.upstream_receipts`.
    """

    handshake_id: str
    request: dict[str, Any]
    iss: str
    sub: str  # the audience of this handshake — i.e. who acts on the request
    capability: Capability
    parent_receipt_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_parent(self, receipt_id: str) -> None:
        """Link an upstream receipt to the receipt this context will emit."""

        if receipt_id and receipt_id not in self.parent_receipt_ids:
            self.parent_receipt_ids.append(receipt_id)


class Handshake:
    """Top-level facade. One per producer DID per process.

    Args:
      registry_url: Base URL of the Phase-3 Registry. POSTs go to
        ``<registry_url>/v1/receipts``.
      kms: signing key provider (`SoftwareKMS` for tests; HSM for prod).
      registry_timeout_s: per-request HTTP timeout.
      offline: if True, sign envelopes locally but do NOT POST to the Registry.
        Useful for unit tests and for agents in air-gapped environments that
        forward receipts to a side-car later.
    """

    def __init__(
        self,
        *,
        registry_url: str = "http://localhost:8080",
        kms: KeyManagementProvider,
        registry_timeout_s: float = 10.0,
        offline: bool = False,
    ) -> None:
        self.registry_url = registry_url.rstrip("/")
        self.kms = kms
        self.registry_timeout_s = registry_timeout_s
        self.offline = offline

    # ---- Phase 1 — DELEGATION ------------------------------------------------
    def delegate(
        self,
        *,
        sub: str,
        aud: str,
        capability: Capability | dict[str, Any],
        duration_s: int = 3600,
        sub_delegation_depth_remaining: int = 0,
        parent_delegation_id: Optional[str] = None,
    ) -> DelegationToken:
        """Issue (and sign) a Delegation Token: `iss → sub` for `capability`.

        `iss` is the producer DID held by `self.kms`. `sub` is the agent (or
        downstream service) that will *use* the capability. `aud` is the
        service the holder will present this delegation to (often the same as
        sub for simple chains).
        """

        cap = capability if isinstance(capability, Capability) else Capability(**capability)
        now = _now_iso()
        nbf = now
        exp = _now_iso(duration_s)
        token = DelegationToken(
            version=SPEC_VERSION,
            kind="DelegationToken",
            id=_ulid("dt"),
            iss=self.kms.did,
            sub=sub,
            aud=aud,
            iat=now,
            nbf=nbf,
            exp=exp,
            capabilities=[cap],
            sub_delegation_depth_remaining=sub_delegation_depth_remaining,
            parent_delegation_id=parent_delegation_id,
            alg=SignatureAlgorithm(self.kms.algorithm()),
        )
        self._sign_envelope(token)
        return token

    # ---- Phase 2 — HANDSHAKE -------------------------------------------------
    def handshake(
        self,
        *,
        aud: str,
        capability: Capability | dict[str, Any],
        delegation_chain: list[DelegationToken],
        nonce: Optional[str] = None,
        agent_attestation: Optional[dict[str, Any]] = None,
    ) -> HandshakeContext:
        """Build + sign a `HandshakeRequest` envelope.

        Returns a `HandshakeContext` the caller carries through the action
        and hands back to `record_receipt()`. We do NOT POST the
        HandshakeRequest anywhere — a well-behaved server middleware
        (`handshake.middleware.fastapi`) will receive it inline as a request
        header and verify it; the receipt is what hits the Registry.
        """

        cap = capability if isinstance(capability, Capability) else Capability(**capability)
        request = HandshakeRequest(
            version=SPEC_VERSION,
            kind="HandshakeRequest",
            id=_ulid("hs"),
            iss=self.kms.did,
            aud=aud,
            iat=_now_iso(),
            nonce=nonce or _b64u(secrets.token_bytes(24)),
            agent_attestation=agent_attestation or {"runtime": "handshake-py", "version": SPEC_VERSION},
            capability=cap,
            delegation_chain=delegation_chain,
            alg=SignatureAlgorithm(self.kms.algorithm()),
        )
        self._sign_envelope(request)
        return HandshakeContext(
            handshake_id=request.id,
            request=request.model_dump(mode="json", exclude_none=True),
            iss=self.kms.did,
            sub=aud,
            capability=cap,
        )

    # ---- Phase 3 — RECEIPT ---------------------------------------------------
    def record_receipt(
        self,
        ctx: HandshakeContext,
        *,
        action: str,
        result: str | ReceiptResult = ReceiptResult.OK,
        result_payload: Any = None,
        upstream_receipts: Optional[list[str]] = None,
        result_summary: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Build + sign a Receipt and POST it to the Registry.

        Returns the dict the Registry returned (containing `receipt_id` and a
        ``leaf_hash``). When ``offline=True`` returns the signed envelope
        without a leaf_hash so callers can persist it themselves.
        """

        result_enum = result if isinstance(result, ReceiptResult) else ReceiptResult(result)
        merged_parents: list[str] = list(ctx.parent_receipt_ids)
        if upstream_receipts:
            for rid in upstream_receipts:
                if rid not in merged_parents:
                    merged_parents.append(rid)

        receipt = Receipt(
            version=SPEC_VERSION,
            kind="Receipt",
            id=_ulid("rc"),
            handshake_id=ctx.handshake_id,
            iss=self.kms.did,
            sub=ctx.sub,
            action=action,
            executed_at=_now_iso(),
            result=result_enum,
            result_hash=_hash_payload(result_payload if result_payload is not None else {}),
            result_summary=result_summary,
            upstream_receipts=merged_parents or None,
            alg=SignatureAlgorithm(self.kms.algorithm()),
        )
        self._sign_envelope(receipt)

        envelope = receipt.model_dump(mode="json", exclude_none=True)
        if self.offline:
            return {"receipt_id": receipt.id, "envelope": envelope, "anchor": None}

        try:
            code, body = _http_post_json(
                f"{self.registry_url}/v1/receipts",
                envelope,
                timeout_s=self.registry_timeout_s,
            )
        except URLError as exc:  # network unreachable, etc.
            raise RegistryError(f"Registry POST failed: {exc!r}") from exc

        if code != 202:
            raise RegistryError(
                f"Registry rejected receipt {receipt.id}: HTTP {code} {body!r}"
            )
        body.setdefault("receipt_id", receipt.id)
        body["envelope"] = envelope
        return body

    # ---- Read side -----------------------------------------------------------
    def fetch_receipt(self, receipt_id: str) -> dict[str, Any]:
        """Read a receipt + inclusion proof from the Registry.

        Returns the raw dict the Registry returned (`{receipt, anchor}`).
        Raises `RegistryError` on any non-200 response.
        """

        code, body = _http_get_json(
            f"{self.registry_url}/v1/receipts/{receipt_id}",
            timeout_s=self.registry_timeout_s,
        )
        if code != 200:
            raise RegistryError(f"GET {receipt_id} failed: HTTP {code} {body!r}")
        return body

    def wait_for_anchor(
        self, receipt_id: str, *, max_wait_s: float = 10.0, poll_s: float = 0.5
    ) -> dict[str, Any]:
        """Block until the receipt's anchor.status == 'anchored', or raise."""

        deadline = time.time() + max_wait_s
        last: dict[str, Any] = {}
        while time.time() < deadline:
            last = self.fetch_receipt(receipt_id)
            if last.get("anchor", {}).get("status") == "anchored":
                return last
            time.sleep(poll_s)
        raise RegistryError(
            f"receipt {receipt_id} not anchored within {max_wait_s}s; last={last!r}"
        )

    # ---- Internals -----------------------------------------------------------
    def _sign_envelope(self, envelope: Any) -> None:
        """Sign a Pydantic envelope in-place — JCS over body minus `signature`.

        Mirrors the demo's `sign_receipt()` byte-for-byte so producer
        envelopes from the SDK are indistinguishable from those produced by
        the canonical signing path.
        """

        body = envelope.model_dump(mode="json", exclude_none=True)
        body.pop("signature", None)
        msg = canonicalize(body)
        sig = self.kms.sign(msg)
        envelope.signature = _b64u(sig)


class RegistryError(RuntimeError):
    """Raised when the Registry rejects or is unreachable for a receipt POST/GET."""


__all__ = [
    "Handshake",
    "HandshakeContext",
    "RegistryError",
    "SPEC_VERSION",
]
