"""OpenAI Agents SDK wrapper.

Drop-in usage::

    from handshake import Handshake
    from handshake.frameworks.openai_agents import wrap

    hs = Handshake(registry_url=..., kms=...)
    runner = wrap(handshake=hs, model_did="did:hsk:openai.gpt-4o")
    out = runner.run(prompt="research the SF Bay weather", upstream_receipts=[parent_id])

Behaviour:
  * `runner.run(prompt=...)` opens a HandshakeContext, invokes the OpenAI
    Agents SDK if available + `OPENAI_API_KEY` is set, and emits a Receipt.
  * Default MOCK mode returns a deterministic stub so the demo runs in CI.

The OpenAI Agents API surface has shifted between releases (`openai.beta.assistants`
→ `openai-agents-python`). The wrapper below targets the simplest stable
contract — a `runner.run(prompt: str) → str` — and adapts the underlying
SDK to it lazily. Production users may want to subclass for richer flows.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from ..client import Handshake
from ..models import Capability


_DEFAULT_CAP = Capability(name="ai.agents.run")


class _MockResponse:
    def __init__(self, prompt: str) -> None:
        self.text = f"[handshake-mock openai-agents] result for: {prompt[:60]}"
        self.tool_calls: list[dict[str, Any]] = []


class OpenAIAgentsHandshakeRunner:
    """Wraps an OpenAI Agents-style `runner.run(prompt) → result`.

    `inner_run` is a callable matching the live SDK's signature; when None,
    the wrapper synthesizes a MOCK response.
    """

    def __init__(
        self,
        handshake: Handshake,
        *,
        model_did: str,
        capability: Capability,
        inner_run: Optional[Any] = None,
    ) -> None:
        self._hs = handshake
        self._model_did = model_did
        self._capability = capability
        self._inner_run = inner_run

    @property
    def is_mock(self) -> bool:
        return self._inner_run is None

    def run(
        self,
        prompt: str,
        *,
        upstream_receipts: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        token = self._hs.delegate(
            sub=self._hs.kms.did,
            aud=self._model_did,
            capability=self._capability,
        )
        ctx = self._hs.handshake(
            aud=self._model_did,
            capability=self._capability,
            delegation_chain=[token],
        )

        if self._inner_run is None:
            response: Any = _MockResponse(prompt)
            text = response.text
        else:
            response = self._inner_run(prompt=prompt, **kwargs)
            text = getattr(response, "text", None) or str(response)

        receipt = self._hs.record_receipt(
            ctx,
            action="openai_agents.run",
            result="ok",
            result_payload={"prompt": prompt, "text": text},
            result_summary={"framework": "openai_agents", "model_did": self._model_did, "mock": self._inner_run is None},
            upstream_receipts=upstream_receipts,
        )
        return {"text": text, "receipt_id": receipt["receipt_id"], "response": response}


def wrap(
    *,
    handshake: Handshake,
    model_did: str = "did:hsk:model.openai.gpt-4o",
    capability: Optional[Capability] = None,
    inner_run: Optional[Any] = None,
) -> OpenAIAgentsHandshakeRunner:
    """Construct a handshake-aware runner.

    If `inner_run` is None and `OPENAI_API_KEY` is set, attempt to
    instantiate a live runner lazily. The OpenAI Agents API moves quickly —
    the lazy import boundary keeps this wrapper compatible across versions
    by failing soft to MOCK if it can't bind a known shape.
    """

    cap = capability or _DEFAULT_CAP
    if inner_run is None and os.environ.get("OPENAI_API_KEY"):
        try:  # pragma: no cover - exercised only when key is present
            from openai import OpenAI  # type: ignore[import-not-found]

            client = OpenAI()

            def _run(*, prompt: str, **kw: Any) -> Any:
                resp = client.responses.create(model=kw.get("model", "gpt-4o-mini"), input=prompt)
                return type(
                    "RunResult",
                    (),
                    {"text": getattr(resp, "output_text", str(resp)), "raw": resp},
                )()

            inner_run = _run
        except Exception:
            inner_run = None
    return OpenAIAgentsHandshakeRunner(
        handshake, model_did=model_did, capability=cap, inner_run=inner_run
    )


__all__ = ["wrap", "OpenAIAgentsHandshakeRunner"]
