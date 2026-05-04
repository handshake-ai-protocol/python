# SPDX-License-Identifier: MIT
"""Phase 2 chain-walk verifier — Python facade.

Wraps the FFI surface (`_native.verify_handshake_request_json` /
`_native.intersect_capabilities_json`) into ergonomic helpers that take
Python-native types and return dataclass-shaped results. The verifier
itself runs entirely in the canonical Rust core — this module is a thin
shim that handles JSON serialization on the way in and result parsing on
the way out, so Python callers see identical semantics to TypeScript and
Rust callers (ADR-0006).

Example (single-instance, process-local nonce tracking via Rust core):

    >>> from handshake.verify import verify_handshake_request, VerifyResult
    >>> result = verify_handshake_request(
    ...     request=signed_request_dict,
    ...     keys={"did:hsk:user:alice": alice_pub_bytes},
    ...     receiver_did="did:hsk:svc:billing",
    ...     now="2026-04-29T14:14:32Z",
    ... )
    >>> result.accepted
    True

SECURITY — multi-instance deployments: the Rust core's built-in nonce
tracking is process-local. In a load-balanced service with multiple pods or
workers, a valid signed request can be replayed against a different worker
within the freshness window (~60 s) because each process tracks seen nonces
independently. Pass ``nonce_store`` to add a cross-instance replay check on
top of the Rust-core verification:

    >>> from my_app.redis_nonce_store import RedisNonceStore
    >>> result = verify_handshake_request(
    ...     request=signed_request_dict,
    ...     keys={"did:hsk:user:alice": alice_pub_bytes},
    ...     receiver_did="did:hsk:svc:billing",
    ...     now="2026-04-29T14:14:32Z",
    ...     nonce_store=RedisNonceStore(redis_client),
    ... )

``nonce_store`` must implement ``check_and_record(nonce: str) -> bool`` —
returning ``True`` if the nonce was already seen (replay), else recording it
and returning ``False``.  For the middleware-level fail-closed API see
``handshake.middleware.fastapi`` and ``handshake.middleware.grpc``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Protocol, Sequence, runtime_checkable

from . import _native  # type: ignore[attr-defined]


@runtime_checkable
class NonceStore(Protocol):
    """Minimal nonce-store interface accepted by ``verify_handshake_request``.

    Implementors must be thread-safe; see the middleware ``NonceStore``
    protocol for the full contract and the ``InMemoryNonceStore`` reference
    implementation.
    """

    def check_and_record(self, nonce: str) -> bool:
        """Return ``True`` if *nonce* was already seen (replay), else record it."""
        ...


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
    nonce_store: Optional[NonceStore] = None,
) -> VerifyResult:
    """Verify a signed `HandshakeRequest`.

    `request` may be a parsed dict or a JSON string; we always reserialize
    via `json.dumps` so the FFI hop is unambiguous. `keys` maps DID strings
    to raw 32-byte Ed25519 public keys (the same shape `ed25519_keypair_from_seed`
    returns). `now` is an RFC 3339 timestamp the verifier uses for the
    freshness window and per-link expiry checks.

    `nonce_store` is an optional cross-instance replay guard. When supplied,
    after the Rust-core verification succeeds the nonce is checked against the
    external store. This is the only way to get distributed replay protection
    for direct verifier callers in multi-instance deployments — the Rust
    core's built-in nonce tracking is process-local. See module docstring for
    usage examples.
    """
    if isinstance(request, str):
        request_json = request
        request_dict: Mapping[str, Any] = json.loads(request_json)
    else:
        request_dict = request
        request_json = json.dumps(request, ensure_ascii=False, separators=(",", ":"))
    payload = _native.verify_handshake_request_json(
        request_json,
        dict(keys),
        receiver_did,
        now,
        list(revoked_principals or []),
        list(revoked_delegations or []),
    )
    result = VerifyResult.from_json(payload)

    # Cross-instance replay check via the injectable nonce store.
    # This supplements the process-local check inside the Rust core, providing
    # distributed replay protection in multi-pod / multi-worker deployments.
    if result.accepted and nonce_store is not None:
        nonce = request_dict.get("nonce")
        if nonce and nonce_store.check_and_record(str(nonce)):
            return VerifyResult(
                accepted=False,
                error_code="replay_detected",
                rejected_at_step="nonce_check",
                detail="nonce already consumed (replay)",
            )

    return result


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


__all__ = ["NonceStore", "VerifyResult", "verify_handshake_request", "intersect_capabilities"]
