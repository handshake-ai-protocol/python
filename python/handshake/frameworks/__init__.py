"""Framework wrappers — drop-in `wrap(client)` for popular agent frameworks.

Each submodule exposes a single `wrap()` function that takes an existing
client (or class) and returns a handshake-aware shim. The shim:

  1. Issues a delegation token (caller → tool/model) on first call.
  2. Opens a `HandshakeContext` per call.
  3. Invokes the underlying client (or runs the MOCK fallback if the
     framework's package isn't installed / no API key is set).
  4. Records a Receipt under the active producer DID.

Wrappers are intentionally thin — the canonical signing and Registry POST
happen in `handshake.client.Handshake`. The wrapper's job is just to
extract a stable `action` name + a hashable result summary from each
framework's idiomatic call shape.
"""

from . import anthropic, langgraph, openai_agents

__all__ = ["anthropic", "openai_agents", "langgraph"]
