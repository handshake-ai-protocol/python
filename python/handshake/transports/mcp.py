# SPDX-License-Identifier: MIT
"""MCP (Model Context Protocol) handshake adapter.

MCP carries arbitrary metadata on each tool invocation. The Handshake wire
binding is:

  * Outgoing: serialize the signed `HandshakeRequest` envelope as JSON,
    base64url-encode, and attach as `_meta.handshake.request_b64u`.
  * Outgoing receipt notification: after the tool replies, post the Receipt
    to the Registry AND echo the receipt id as
    `_meta.handshake.receipt_id` so the caller can link.
  * Incoming server: parse `_meta.handshake.request_b64u`, verify with
    `verify_handshake_request`, mount on tool context.

This module ships a lightweight envelope-mounter; tying it to a specific
MCP client/server SDK is a one-liner.
"""

from __future__ import annotations

import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Any, Optional

from ..client import HandshakeContext


def encode_request(ctx: HandshakeContext) -> str:
    """Serialize a HandshakeRequest into the `_meta` field's base64url form."""
    return urlsafe_b64encode(json.dumps(ctx.request).encode()).rstrip(b"=").decode()


def decode_request(b64u: str) -> dict[str, Any]:
    pad = (-len(b64u)) % 4
    raw = urlsafe_b64decode(b64u + ("=" * pad))
    parsed: dict[str, Any] = json.loads(raw)
    return parsed


def attach(payload: dict[str, Any], ctx: HandshakeContext) -> dict[str, Any]:
    """Stamp the signed HandshakeRequest envelope onto an MCP tool call payload.

    Mutates `payload['_meta']['handshake']` in-place and returns the payload.
    """

    meta = payload.setdefault("_meta", {})
    meta["handshake"] = {
        "request_b64u": encode_request(ctx),
        "spec_version": ctx.request.get("version"),
    }
    return payload


def extract(payload: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Pull the HandshakeRequest dict out of an inbound MCP payload, or None."""

    meta = payload.get("_meta") or {}
    hs = meta.get("handshake") or {}
    b64u = hs.get("request_b64u")
    if not b64u:
        return None
    return decode_request(b64u)


def stamp_receipt_id(payload: dict[str, Any], receipt_id: str) -> dict[str, Any]:
    """Echo the receipt id back to the caller so it can build the DAG."""

    meta = payload.setdefault("_meta", {})
    meta.setdefault("handshake", {})["receipt_id"] = receipt_id
    return payload


__all__ = ["attach", "extract", "encode_request", "decode_request", "stamp_receipt_id"]
