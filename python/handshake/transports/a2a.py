# SPDX-License-Identifier: MIT
"""A2A (Agent-to-Agent) handshake adapter.

A2A wraps each agent message in an envelope with `headers`. The Handshake
binding mirrors HTTP — the signed HandshakeRequest goes on a single header,
the receipt id rides back in the response headers.

  * Outgoing: `headers['X-Handshake-Request']` = base64url JSON of the request.
  * Inbound verify: read the same header.
  * Receipt link-back: `headers['X-Handshake-Receipt']` = receipt id.

This module provides pure-data helpers; bind them into your A2A client's
hooks (e.g. `client.before_send`, `server.before_handler`).
"""

from __future__ import annotations

import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Any, Optional

from ..client import HandshakeContext

REQUEST_HEADER = "X-Handshake-Request"
RECEIPT_HEADER = "X-Handshake-Receipt"


def stamp_request(headers: dict[str, str], ctx: HandshakeContext) -> dict[str, str]:
    headers[REQUEST_HEADER] = urlsafe_b64encode(json.dumps(ctx.request).encode()).rstrip(b"=").decode()
    return headers


def extract_request(headers: dict[str, str]) -> Optional[dict[str, Any]]:
    val = headers.get(REQUEST_HEADER) or headers.get(REQUEST_HEADER.lower())
    if not val:
        return None
    pad = (-len(val)) % 4
    parsed: dict[str, Any] = json.loads(urlsafe_b64decode(val + ("=" * pad)))
    return parsed


def stamp_receipt(headers: dict[str, str], receipt_id: str) -> dict[str, str]:
    headers[RECEIPT_HEADER] = receipt_id
    return headers


__all__ = ["stamp_request", "extract_request", "stamp_receipt", "REQUEST_HEADER", "RECEIPT_HEADER"]
