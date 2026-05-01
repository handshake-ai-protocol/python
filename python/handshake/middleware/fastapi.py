"""FastAPI middleware — `FastAPIHandshakeMiddleware`.

Mounts inbound HandshakeRequest verification + outbound Receipt emission on
every request to a FastAPI service. Designed for the *server side* of a
handshake: the agent calling the service signs an envelope, we verify it,
the handler runs, and we record a receipt of the work.

Usage::

    from fastapi import FastAPI
    from handshake import Handshake
    from handshake.middleware.fastapi import FastAPIHandshakeMiddleware

    hs = Handshake(registry_url=..., kms=...)
    app = FastAPI()
    app.add_middleware(
        FastAPIHandshakeMiddleware,
        handshake=hs,
        keys={"did:hsk:caller-1": caller_pubkey_bytes},
        receiver_did="did:hsk:my-service",
    )

The middleware mounts `request.state.handshake` containing the verified
request envelope and the `effective_constraints`. Handlers should use
`request.state.handshake.context` to record receipts that link to the
inbound handshake_id.
"""

from __future__ import annotations

import json
from base64 import urlsafe_b64decode
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Protocol, runtime_checkable

from ..client import Handshake, HandshakeContext
from ..models import Capability
from ..verify import verify_handshake_request, VerifyResult


def _utcnow_iso() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

REQUEST_HEADER = "x-handshake-request"


@runtime_checkable
class NonceStore(Protocol):
    """Injectable nonce store for cross-instance replay protection.

    Production deployments should back this with a shared store (Redis,
    Postgres, etc.) so that a nonce consumed by one pod/worker/process
    is rejected by all others within the freshness window.

    The built-in in-process store used by the Rust verifier core is only
    safe for single-instance deployments.

    ``check_and_record`` must be thread-safe / coroutine-safe as
    appropriate for the deployment's concurrency model.
    """

    def check_and_record(self, nonce: str) -> bool:
        """Return ``True`` if *nonce* was already seen (replay), else record it."""
        ...


class InMemoryNonceStore:
    """Default in-process nonce store (process-local, not suitable for multi-instance).

    **Limitations:**

    * **Memory growth:** nonces are stored indefinitely in a ``set`` for the
      lifetime of the process.  Under sustained traffic this will grow without
      bound.  For long-lived services use a TTL-aware backend (e.g. Redis
      ``SET EX``) or implement eviction in a custom ``NonceStore``.
    * **Single process only:** each instance keeps an independent store, so a
      nonce consumed on one pod/worker is not known to others.  Cross-instance
      replay protection requires a shared backend.

    Use only for single-instance services, short-lived processes, or tests.
    """

    def __init__(self) -> None:
        import threading
        self._lock = threading.Lock()
        self._seen: set[str] = set()

    def check_and_record(self, nonce: str) -> bool:
        with self._lock:
            if nonce in self._seen:
                return True
            self._seen.add(nonce)
            return False


@dataclass
class HandshakeRequestState:
    """Mounted on `request.state.handshake` after verification.

    `context` is a synthesized `HandshakeContext` so handler code can call
    `hs.record_receipt(state.handshake.context, action=…, …)` without
    rebuilding the envelope.
    """

    request: dict[str, Any]
    verify_result: VerifyResult
    context: HandshakeContext
    parent_handshake_id: str
    parent_iss: str
    parent_aud: str = field(default="")


def _decode_b64u(s: str) -> bytes:
    pad = (-len(s)) % 4
    return urlsafe_b64decode(s + ("=" * pad))


class FastAPIHandshakeMiddleware:
    """ASGI middleware factory.

    Args:
      handshake: outbound `Handshake` for emitting receipts under the
        SERVICE's DID. Distinct from the caller's producer Handshake.
      keys: mapping `did → public_key_bytes` for chain-walk verification.
        In production this is backed by a DID resolver (the Phase-3 Registry
        publishes the same data at `/v1/dids/<did>`); for local dev pass an
        explicit dict.
      receiver_did: the DID of THIS service. Verifier rejects envelopes whose
        `aud` doesn't match.
      nonce_store: optional injectable nonce store for cross-instance replay
        protection.  When not supplied the middleware relies solely on the
        process-local nonce tracking built into the Rust verifier core, which
        is *not* safe in multi-instance deployments.  Supply a shared backend
        (Redis, Postgres, …) to get cross-pod replay rejection.
    """

    def __init__(
        self,
        app: Any,
        *,
        handshake: Handshake,
        keys: Mapping[str, bytes],
        receiver_did: str,
        require: bool = True,
        nonce_store: Optional[NonceStore] = None,
    ) -> None:
        self.app = app
        self.handshake = handshake
        self.keys = dict(keys)
        self.receiver_did = receiver_did
        self.require = require
        self.nonce_store = nonce_store

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        b64u = headers.get(REQUEST_HEADER)
        if not b64u:
            if self.require:
                await self._reject(send, 401, {"code": "handshake_missing", "message": f"missing {REQUEST_HEADER} header"})
                return
            await self.app(scope, receive, send)
            return

        try:
            req = json.loads(_decode_b64u(b64u))
        except Exception as exc:
            await self._reject(send, 400, {"code": "handshake_malformed", "message": str(exc)})
            return

        result = verify_handshake_request(
            request=req,
            keys=self.keys,
            receiver_did=self.receiver_did,
            now=_utcnow_iso(),
        )
        if not result.accepted:
            await self._reject(send, 403, {
                "code": result.error_code or "handshake_rejected",
                "message": result.detail or "handshake verification failed",
            })
            return

        # Cross-instance replay check using the injectable nonce store.
        if self.nonce_store is not None:
            nonce = req.get("nonce")
            if nonce and self.nonce_store.check_and_record(str(nonce)):
                await self._reject(send, 403, {
                    "code": "replay_detected",
                    "message": "nonce already consumed (replay)",
                })
                return

        # Build a HandshakeContext under the SERVICE's identity so handler
        # code can emit a receipt that's signed by the service (the work-doer).
        cap_data = req.get("capability") or {}
        cap = Capability(name=cap_data.get("name", "unknown"), constraints=cap_data.get("constraints"))
        ctx = HandshakeContext(
            handshake_id=req["id"],
            request=req,
            iss=self.handshake.kms.did,
            sub=req["aud"],
            capability=cap,
        )
        state = HandshakeRequestState(
            request=req,
            verify_result=result,
            context=ctx,
            parent_handshake_id=req["id"],
            parent_iss=req["iss"],
            parent_aud=req["aud"],
        )
        # ASGI scope mutation: stash the verified envelope where Starlette's
        # Request.state can pick it up.
        scope.setdefault("state", {})["handshake"] = state

        await self.app(scope, receive, send)

    async def _reject(self, send: Any, status: int, detail: dict[str, Any]) -> None:
        body = json.dumps({"detail": detail}).encode()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body, "more_body": False})


__all__ = [
    "FastAPIHandshakeMiddleware",
    "HandshakeRequestState",
    "InMemoryNonceStore",
    "NonceStore",
    "REQUEST_HEADER",
]
