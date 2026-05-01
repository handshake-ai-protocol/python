"""Phase 2 chain-walk verifier — Python facade.

Wraps the FFI surface (`_native.verify_handshake_request_json` /
`_native.intersect_capabilities_json`) into ergonomic helpers that take
Python-native types and return dataclass-shaped results. The verifier
itself runs entirely in the canonical Rust core — this module is a thin
shim that handles JSON serialization on the way in and result parsing on
the way out, so Python callers see identical semantics to TypeScript and
Rust callers (ADR-0006).

Example:
    >>> from handshake.verify import verify_handshake_request, VerifyResult
    >>> result = verify_handshake_request(
    ...     request=signed_request_dict,
    ...     keys={"did:hsk:user:alice": alice_pub_bytes},
    ...     receiver_did="did:hsk:svc:billing",
    ...     now="2026-04-29T14:14:32Z",
    ... )
    >>> result.accepted
    True
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from . import _native  # type: ignore[attr-defined]


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of a `verify_handshake_request` call.

    On accept: `accepted=True`, `capability` and `effective_constraints` set,
    refusal fields all None. On reject: `accepted=False`, `error_code` and
    `rejected_at_step` set per `_common.json#/$defs/errorCode`, plus a human-
    readable `detail` and (for chain-walk rejections) `rejected_delegation_id`.
    """

    accepted: bool
    capability: str | None = None
    effective_constraints: dict[str, Any] | None = None
    error_code: str | None = None
    rejected_at_step: str | None = None
    detail: str | None = None
    rejected_delegation_id: str | None = None

    @classmethod
    def from_json(cls, payload: str) -> "VerifyResult":
        data = json.loads(payload)
        if data.get("result") == "accept":
            return cls(
                accepted=True,
                capability=data.get("capability"),
                effective_constraints=data.get("effective_constraints") or {},
            )
        return cls(
            accepted=False,
            error_code=data.get("error_code"),
            rejected_at_step=data.get("rejected_at_step"),
            detail=data.get("detail"),
            rejected_delegation_id=data.get("rejected_delegation_id"),
        )


def verify_handshake_request(
    request: Mapping[str, Any] | str,
    keys: Mapping[str, bytes],
    receiver_did: str,
    now: str,
    revoked_principals: Sequence[str] | None = None,
    revoked_delegations: Sequence[str] | None = None,
) -> VerifyResult:
    """Verify a signed `HandshakeRequest`.

    `request` may be a parsed dict or a JSON string; we always reserialize
    via `json.dumps` so the FFI hop is unambiguous. `keys` maps DID strings
    to raw 32-byte Ed25519 public keys (the same shape `ed25519_keypair_from_seed`
    returns). `now` is an RFC 3339 timestamp the verifier uses for the
    freshness window and per-link expiry checks.
    """
    if isinstance(request, str):
        request_json = request
    else:
        request_json = json.dumps(request, ensure_ascii=False, separators=(",", ":"))
    payload = _native.verify_handshake_request_json(
        request_json,
        dict(keys),
        receiver_did,
        now,
        list(revoked_principals or []),
        list(revoked_delegations or []),
    )
    return VerifyResult.from_json(payload)


def intersect_capabilities(
    delegated: Mapping[str, Any],
    requested: Mapping[str, Any],
) -> dict[str, Any]:
    """Intersect two capability constraint dicts.

    Returns the parsed JSON outcome:
    - `{"ok": True, "effective": { ... }}` when admissible.
    - `{"ok": False, "error_code": "scope_exceeded", "key": "...", "reason": "..."}` otherwise.
    """
    payload = _native.intersect_capabilities_json(
        json.dumps(delegated, ensure_ascii=False, separators=(",", ":")),
        json.dumps(requested, ensure_ascii=False, separators=(",", ":")),
    )
    parsed: dict[str, Any] = json.loads(payload)
    return parsed


__all__ = ["VerifyResult", "verify_handshake_request", "intersect_capabilities"]
