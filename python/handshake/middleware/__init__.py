"""Server-side middleware — verify inbound HandshakeRequest, emit Receipt.

A protected service (the consumer of a capability) needs to:
  1. Pull the inbound HandshakeRequest off the request,
  2. Resolve the issuer DID's public key,
  3. Verify the chain (`verify_handshake_request`),
  4. On accept, run the handler,
  5. Emit a Receipt linking the inbound request to the work done.

These middlewares package that loop for FastAPI and gRPC. They are
thin — verification stays in the canonical Rust verifier; the middleware
just plumbs request → handler → receipt.
"""

from . import fastapi as fastapi_mw  # noqa: F401
from . import grpc as grpc_mw  # noqa: F401

__all__ = ["fastapi_mw", "grpc_mw"]
