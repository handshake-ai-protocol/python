"""gRPC server interceptor — `gRPCHandshakeInterceptor`.

Mirrors the FastAPI middleware but for gRPC: pulls the HandshakeRequest
off `metadata`, verifies it, mounts a `HandshakeContext` on the
`ServicerContext` via a custom attribute, then dispatches.

Usage::

    import grpc
    from handshake import Handshake
    from handshake.middleware.grpc import gRPCHandshakeInterceptor

    interceptor = gRPCHandshakeInterceptor(
        handshake=Handshake(...),
        keys={"did:hsk:caller-1": pubkey_bytes},
        receiver_did="did:hsk:my-grpc-service",
    )
    server = grpc.server(thread_pool, interceptors=[interceptor])

This module declines a hard `grpc` dependency at import time — it imports
the package lazily and exposes a no-op fallback so unit tests can probe
the verifier path without grpcio installed.
"""

from __future__ import annotations

import json
from base64 import urlsafe_b64decode
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Mapping, Optional, Protocol, runtime_checkable

from ..client import Handshake, HandshakeContext
from ..models import Capability
from ..verify import verify_handshake_request, VerifyResult


def _utcnow_iso() -> str:
    """Return RFC 3339 timestamp without sub-second precision (matches spec)."""
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

METADATA_KEY = "x-handshake-request"


def _decode_b64u(s: str) -> bytes:
    pad = (-len(s)) % 4
    return urlsafe_b64decode(s + ("=" * pad))


@runtime_checkable
class NonceStore(Protocol):
    """Injectable nonce store for cross-instance replay protection.

    Production deployments should back this with a shared store (Redis,
    Postgres, etc.) so that a nonce consumed by one pod/worker/process
    is rejected by all others within the freshness window.

    The built-in in-process store is only safe for single-instance
    deployments; see ``InMemoryNonceStore``.

    ``check_and_record`` must be thread-safe (called from concurrent
    request-handling threads).
    """

    def check_and_record(self, nonce: str) -> bool:
        """Return ``True`` if *nonce* was already seen (replay), else record it.

        Must be thread-safe.
        """
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
class HandshakeRpcState:
    """Stashed on `context.handshake_state` after verification."""

    request: dict[str, Any]
    verify_result: VerifyResult
    context: HandshakeContext


def verify_metadata(
    metadata: Mapping[str, str] | list[tuple[str, str]],
    *,
    keys: Mapping[str, bytes],
    receiver_did: str,
    handshake: Handshake,
) -> tuple[bool, HandshakeRpcState | dict[str, str]]:
    """Pure helper: parse + verify a metadata dict, return (ok, state | err).

    Extracted so gRPC-less unit tests can exercise the same logic.
    """

    md = dict(metadata) if not isinstance(metadata, dict) else dict(metadata)
    b64u = md.get(METADATA_KEY) or md.get(METADATA_KEY.upper())
    if not b64u:
        return False, {"code": "handshake_missing", "message": f"missing {METADATA_KEY} metadata"}
    try:
        req = json.loads(_decode_b64u(b64u))
    except Exception as exc:
        return False, {"code": "handshake_malformed", "message": str(exc)}

    result = verify_handshake_request(
        request=req,
        keys=dict(keys),
        receiver_did=receiver_did,
        now=_utcnow_iso(),
    )
    if not result.accepted:
        return False, {
            "code": result.error_code or "handshake_rejected",
            "message": result.detail or "handshake verification failed",
        }

    cap_data = req.get("capability") or {}
    cap = Capability(name=cap_data.get("name", "unknown"), constraints=cap_data.get("constraints"))
    ctx = HandshakeContext(
        handshake_id=req["id"],
        request=req,
        iss=handshake.kms.did,
        sub=req["aud"],
        capability=cap,
    )
    return True, HandshakeRpcState(request=req, verify_result=result, context=ctx)


class gRPCHandshakeInterceptor:
    """A `grpc.ServerInterceptor` (duck-typed; we only import grpc lazily).

    On every RPC — unary-unary, unary-stream, stream-unary, and
    stream-stream — parse + verify the inbound HandshakeRequest in
    metadata. Reject with ``UNAUTHENTICATED`` if missing or invalid.

    Args:
        handshake: outbound ``Handshake`` used to build the verified
            ``HandshakeContext``.
        keys: mapping ``did → raw 32-byte Ed25519 public key``.
        receiver_did: DID of THIS service; the verifier rejects envelopes
            whose ``aud`` does not match.
        require: when ``False``, RPCs that carry no or invalid metadata
            are passed through instead of rejected (useful for mixed
            public/private services).
        nonce_store: optional injectable nonce store for cross-instance
            replay protection.  When not supplied the interceptor relies
            solely on the process-local nonce tracking built into the
            Rust verifier core, which is *not* safe in multi-instance
            deployments.  Supply a shared backend (Redis, Postgres, …)
            to get cross-pod replay rejection.
    """

    def __init__(
        self,
        *,
        handshake: Handshake,
        keys: Mapping[str, bytes],
        receiver_did: str,
        require: bool = True,
        nonce_store: Optional[NonceStore] = None,
    ) -> None:
        self.handshake = handshake
        self.keys = dict(keys)
        self.receiver_did = receiver_did
        self.require = require
        self.nonce_store = nonce_store

    def _make_verify_fn(self) -> Callable[[Any], tuple[bool, Any]]:
        """Return a callable that verifies metadata and returns (ok, state|err)."""
        keys = self.keys
        receiver_did = self.receiver_did
        handshake = self.handshake
        nonce_store = self.nonce_store

        def _verify(context: Any) -> tuple[bool, Any]:
            md = dict(context.invocation_metadata()) if hasattr(context, "invocation_metadata") else {}
            ok, payload = verify_metadata(md, keys=keys, receiver_did=receiver_did, handshake=handshake)
            if not ok:
                return False, payload
            if nonce_store is not None:
                req = payload.request  # type: ignore[union-attr]
                nonce = req.get("nonce")
                if nonce and nonce_store.check_and_record(str(nonce)):
                    return False, {"code": "replay_detected", "message": "nonce already consumed (replay)"}
            return True, payload

        return _verify

    def intercept_service(self, continuation: Callable[..., Any], handler_call_details: Any) -> Any:
        """grpc.ServerInterceptor.intercept_service — wraps all RPC types."""

        try:
            import grpc  # type: ignore[import-untyped]
        except Exception:
            return continuation(handler_call_details)

        original = continuation(handler_call_details)
        if original is None:
            return None

        require = self.require
        _verify = self._make_verify_fn()

        def _reject_with(context: Any, payload: dict[str, str]) -> None:
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details(json.dumps(payload))

        # --- unary-unary ---
        if getattr(original, "unary_unary", None):
            original_handler = original.unary_unary

            def new_unary_unary(request: Any, context: Any) -> Any:
                ok, payload = _verify(context)
                if not ok:
                    if require:
                        _reject_with(context, payload)
                        return None
                else:
                    setattr(context, "handshake_state", payload)
                return original_handler(request, context)

            return grpc.unary_unary_rpc_method_handler(
                new_unary_unary,
                request_deserializer=original.request_deserializer,
                response_serializer=original.response_serializer,
            )

        # --- unary-stream ---
        if getattr(original, "unary_stream", None):
            original_handler = original.unary_stream

            def new_unary_stream(request: Any, context: Any) -> Iterator[Any]:
                ok, payload = _verify(context)
                if not ok:
                    if require:
                        _reject_with(context, payload)
                        return
                else:
                    setattr(context, "handshake_state", payload)
                yield from original_handler(request, context)

            return grpc.unary_stream_rpc_method_handler(
                new_unary_stream,
                request_deserializer=original.request_deserializer,
                response_serializer=original.response_serializer,
            )

        # --- stream-unary ---
        if getattr(original, "stream_unary", None):
            original_handler = original.stream_unary

            def new_stream_unary(request_iterator: Any, context: Any) -> Any:
                ok, payload = _verify(context)
                if not ok:
                    if require:
                        _reject_with(context, payload)
                        return None
                else:
                    setattr(context, "handshake_state", payload)
                return original_handler(request_iterator, context)

            return grpc.stream_unary_rpc_method_handler(
                new_stream_unary,
                request_deserializer=original.request_deserializer,
                response_serializer=original.response_serializer,
            )

        # --- stream-stream ---
        if getattr(original, "stream_stream", None):
            original_handler = original.stream_stream

            def new_stream_stream(request_iterator: Any, context: Any) -> Iterator[Any]:
                ok, payload = _verify(context)
                if not ok:
                    if require:
                        _reject_with(context, payload)
                        return
                else:
                    setattr(context, "handshake_state", payload)
                yield from original_handler(request_iterator, context)

            return grpc.stream_stream_rpc_method_handler(
                new_stream_stream,
                request_deserializer=original.request_deserializer,
                response_serializer=original.response_serializer,
            )

        return original


__all__ = [
    "gRPCHandshakeInterceptor",
    "HandshakeRpcState",
    "InMemoryNonceStore",
    "NonceStore",
    "verify_metadata",
    "METADATA_KEY",
]
