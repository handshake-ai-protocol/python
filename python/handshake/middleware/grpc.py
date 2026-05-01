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
from typing import Any, Callable, Mapping

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

    On every RPC, parse + verify the inbound HandshakeRequest in metadata.
    Reject with `UNAUTHENTICATED` if missing or invalid.
    """

    def __init__(
        self,
        *,
        handshake: Handshake,
        keys: Mapping[str, bytes],
        receiver_did: str,
        require: bool = True,
    ) -> None:
        self.handshake = handshake
        self.keys = dict(keys)
        self.receiver_did = receiver_did
        self.require = require

    def intercept_service(self, continuation: Callable[..., Any], handler_call_details: Any) -> Any:
        """grpc.ServerInterceptor.intercept_service — wrapped to inject state."""

        try:
            import grpc  # type: ignore[import-untyped]
        except Exception:
            return continuation(handler_call_details)

        original = continuation(handler_call_details)
        if original is None:
            return None
        keys = self.keys
        receiver_did = self.receiver_did
        handshake = self.handshake
        require = self.require

        # Wrap UNARY_UNARY only — for streaming variants, real users will
        # subclass; the verification helper above is shape-agnostic.
        if not getattr(original, "unary_unary", None):
            return original

        original_unary = original.unary_unary

        def new_unary(request: Any, context: Any) -> Any:
            md = dict(context.invocation_metadata()) if hasattr(context, "invocation_metadata") else {}
            ok, payload = verify_metadata(
                md, keys=keys, receiver_did=receiver_did, handshake=handshake
            )
            if not ok:
                if require:
                    context.set_code(grpc.StatusCode.UNAUTHENTICATED)
                    context.set_details(json.dumps(payload))
                    return None
            else:
                setattr(context, "handshake_state", payload)
            return original_unary(request, context)

        return grpc.unary_unary_rpc_method_handler(
            new_unary,
            request_deserializer=original.request_deserializer,
            response_serializer=original.response_serializer,
        )


__all__ = ["gRPCHandshakeInterceptor", "HandshakeRpcState", "verify_metadata", "METADATA_KEY"]
