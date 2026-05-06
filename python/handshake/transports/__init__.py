# SPDX-License-Identifier: MIT
"""Transport adapters — bind Handshake envelopes to wire protocols.

Each submodule exposes `attach(transport_obj, handshake)` (or equivalent)
that registers handshake-aware send/receive hooks on an MCP, A2A, or AP2
client. The adapters are intentionally narrow — the heavy lifting lives in
`handshake.client.Handshake`; the transport code only translates header
formats.

See the Handshake protocol specification for the canonical wire-format
definitions of the ``X-Handshake-*`` headers consumed by each adapter.
"""

from . import a2a, ap2, mcp

__all__ = ["mcp", "a2a", "ap2"]
