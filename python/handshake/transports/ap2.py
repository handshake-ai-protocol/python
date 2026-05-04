# SPDX-License-Identifier: MIT
"""AP2 (Agent Payments Protocol) handshake adapter.

AP2 carries payment-mandate envelopes on each call. The Handshake binding:

  * The HandshakeRequest is embedded inside the payment mandate as
    `mandate['attestations']['handshake']`. This co-locates the agent
    capability proof with the payment authorization, which is what AP2
    auditors expect.
  * The Receipt id is reflected back inside the payment receipt's
    `attestations.handshake_receipt` field.

Spec note: AP2 doesn't yet have a published normative binding for
Handshake, so the field paths above are advisory; the auditor SHOULD
accept either the mandate-embedded form or a sibling `handshake` envelope.
"""

from __future__ import annotations

from typing import Any, Optional

from ..client import HandshakeContext


def attach_to_mandate(mandate: dict[str, Any], ctx: HandshakeContext) -> dict[str, Any]:
    """Embed the HandshakeRequest inside an AP2 payment mandate."""

    attestations = mandate.setdefault("attestations", {})
    attestations["handshake"] = ctx.request
    return mandate


def extract_from_mandate(mandate: dict[str, Any]) -> Optional[dict[str, Any]]:
    return (mandate.get("attestations") or {}).get("handshake")


def stamp_receipt_on_payment(payment_receipt: dict[str, Any], receipt_id: str) -> dict[str, Any]:
    attestations = payment_receipt.setdefault("attestations", {})
    attestations["handshake_receipt"] = receipt_id
    return payment_receipt


__all__ = ["attach_to_mandate", "extract_from_mandate", "stamp_receipt_on_payment"]
