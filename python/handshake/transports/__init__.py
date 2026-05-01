"""Transport adapters — bind Handshake envelopes to wire protocols.

Each submodule exposes `attach(transport_obj, handshake)` (or equivalent)
that registers handshake-aware send/receive hooks on an MCP, A2A, or AP2
client. The adapters are intentionally narrow — the heavy lifting lives in
`handshake.client.Handshake`; the transport code only translates header
formats.

For a deep dive on the wire formats, see the handoff document
(`attached_assets/Replit_Build_Handoff_*.md`) §5.
"""

from . import a2a, ap2, mcp

__all__ = ["mcp", "a2a", "ap2"]
