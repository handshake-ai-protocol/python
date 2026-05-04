# SPDX-License-Identifier: MIT
"""LangGraph wrapper — `wrap_node()` for graph-bound agent steps.

LangGraph nodes are pure functions `(state) → state_patch`. Production
flows compose dozens; auditing each as a Receipt makes the cross-framework
DAG demo work without modifying user code.

Usage::

    from handshake import Handshake
    from handshake.frameworks.langgraph import wrap_node

    hs = Handshake(registry_url=..., kms=...)

    def search_node(state):
        return {"results": ["a", "b"]}

    audited = wrap_node(
        search_node,
        handshake=hs,
        action="langgraph.search",
        tool_did="did:hsk:tool.langgraph.search",
    )
    new_state = audited({"query": "foo"})  # also writes a Receipt

The wrapper threads receipt ids through the state under
`state["_handshake_receipts"]` so downstream nodes can pick them up via
`upstream_receipts=[…]` automatically.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from ..client import Handshake
from ..models import Capability


_DEFAULT_CAP = Capability(name="ai.langgraph.node")


def wrap_node(
    fn: Callable[..., Any],
    *,
    handshake: Handshake,
    action: str,
    tool_did: str,
    capability: Optional[Capability] = None,
) -> Callable[..., Any]:
    """Return a node function that audits each invocation as a Receipt."""

    cap = capability or _DEFAULT_CAP

    def audited(state: dict[str, Any], *args: Any, **kwargs: Any) -> dict[str, Any]:
        token = handshake.delegate(
            sub=handshake.kms.did, aud=tool_did, capability=cap
        )
        ctx = handshake.handshake(
            aud=tool_did, capability=cap, delegation_chain=[token]
        )

        upstream = state.get("_handshake_receipts", []) if isinstance(state, dict) else []
        result_patch = fn(state, *args, **kwargs) or {}

        receipt = handshake.record_receipt(
            ctx,
            action=action,
            result="ok",
            result_payload={"patch": result_patch},
            result_summary={"framework": "langgraph", "node": action},
            upstream_receipts=list(upstream),
        )
        # Append our id so downstream nodes pick it up.
        if isinstance(result_patch, dict):
            new_chain: list[str] = list(upstream) + [receipt["receipt_id"]]
            result_patch.setdefault("_handshake_receipts", new_chain)
        return result_patch

    audited.__name__ = f"audited_{getattr(fn, '__name__', 'node')}"
    audited.__doc__ = (fn.__doc__ or "") + "\n\n[wrapped by handshake.frameworks.langgraph]"
    return audited


__all__ = ["wrap_node"]
