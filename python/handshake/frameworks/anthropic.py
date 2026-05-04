# SPDX-License-Identifier: MIT
"""Anthropic SDK wrapper — `Handshake.wrap(client)` for `anthropic.Anthropic`.

Drop-in usage::

    import anthropic
    from handshake import Handshake
    from handshake.frameworks.anthropic import wrap

    hs = Handshake(registry_url=..., kms=...)
    client = wrap(anthropic.Anthropic(), handshake=hs, model_did="did:hsk:claude")
    msg = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=256,
        messages=[{"role": "user", "content": "hi"}],
    )

Behaviour:
  * Each `messages.create` call brackets in a `HandshakeContext`.
  * The result text (or its serialized JSON form when running under MOCK)
    is hashed into the Receipt's `result_hash`.
  * If the `anthropic` package isn't installed OR no `ANTHROPIC_API_KEY` is
    set, the wrapper falls back to a deterministic MOCK that returns a
    stub response — receipts still post to the Registry, so the demo
    runs hermetically in CI.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from ..client import Handshake, HandshakeContext
from ..models import Capability


_DEFAULT_CAP = Capability(name="ai.completions.create")


class _MockMessage:
    """Stub object shaped like `anthropic.types.Message`. Carries the same
    `.content[0].text` shape so caller code works in MOCK mode unchanged."""

    class _ContentBlock:
        def __init__(self, text: str) -> None:
            self.type = "text"
            self.text = text

    def __init__(self, model: str, prompt: str) -> None:
        self.id = "msg_mock_handshake"
        self.model = model
        self.role = "assistant"
        self.stop_reason = "end_turn"
        self.content = [self._ContentBlock(f"[handshake-mock claude] echo: {prompt}")]
        self.usage = type("Usage", (), {"input_tokens": 7, "output_tokens": 11})()


class _Messages:
    """Wraps the `client.messages` namespace."""

    def __init__(
        self,
        inner: Optional[Any],
        handshake: Handshake,
        model_did: str,
        capability: Capability,
        producer_kms_did: str,
    ) -> None:
        self._inner = inner
        self._hs = handshake
        self._model_did = model_did
        self._capability = capability
        self._producer = producer_kms_did

    def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        upstream_receipts: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> Any:
        token = self._hs.delegate(
            sub=self._producer,
            aud=self._model_did,
            capability=self._capability,
        )
        ctx = self._hs.handshake(
            aud=self._model_did,
            capability=self._capability,
            delegation_chain=[token],
        )

        if self._inner is None:
            # MOCK fallback. We still produce a well-shaped response so
            # caller code doesn't need to branch on env.
            prompt = next(
                (m.get("content", "") for m in messages if m.get("role") == "user"),
                "",
            )
            response: Any = _MockMessage(model=model, prompt=str(prompt))
            text_out = response.content[0].text
        else:
            response = self._inner.create(model=model, messages=messages, **kwargs)
            try:
                text_out = response.content[0].text
            except Exception:
                text_out = str(response)

        receipt = self._hs.record_receipt(
            ctx,
            action="anthropic.messages.create",
            result="ok",
            result_payload={"model": model, "text": text_out},
            result_summary={
                "framework": "anthropic",
                "model": model,
                "mock": self._inner is None,
            },
            upstream_receipts=upstream_receipts,
        )
        # Stamp the receipt id on the response so downstream callers can
        # link follow-on receipts via `upstream_receipts=[…]`.
        try:
            setattr(response, "handshake_receipt_id", receipt["receipt_id"])
        except Exception:
            pass
        return response


class AnthropicHandshakeClient:
    """Drop-in shim around `anthropic.Anthropic` (or None for MOCK)."""

    def __init__(
        self,
        inner: Optional[Any],
        handshake: Handshake,
        model_did: str,
        capability: Capability,
    ) -> None:
        self._inner = inner
        self.handshake = handshake
        self.messages = _Messages(
            inner.messages if inner is not None else None,
            handshake,
            model_did,
            capability,
            handshake.kms.did,
        )

    @property
    def is_mock(self) -> bool:
        return self._inner is None


def wrap(
    client: Optional[Any] = None,
    *,
    handshake: Handshake,
    model_did: str = "did:hsk:model.anthropic.claude",
    capability: Optional[Capability] = None,
) -> AnthropicHandshakeClient:
    """Wrap an `anthropic.Anthropic` instance (or pass `None` for MOCK).

    If `client` is None and `ANTHROPIC_API_KEY` is set, we attempt to
    construct a real client lazily — the `anthropic` package only loads
    on that path, so the MOCK path never imports it.
    """

    cap = capability or _DEFAULT_CAP
    if client is None and os.environ.get("ANTHROPIC_API_KEY"):
        try:
            import anthropic as _anthropic  # type: ignore[import-not-found]  # noqa: F401

            client = _anthropic.Anthropic()
        except Exception:
            client = None  # fall through to MOCK
    return AnthropicHandshakeClient(client, handshake, model_did, cap)


__all__ = ["wrap", "AnthropicHandshakeClient"]
