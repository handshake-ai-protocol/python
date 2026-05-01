"""Operator audit-trail interface (Phase 6 hook).

The Console (Phase 6) lets a human operator perform sensitive actions
on the Registry: pause a tenant, rotate a DID, revoke a delegation,
override a policy decision. Every such action must produce a signed
receipt indistinguishable from a runtime call — same envelope shape,
same Ed25519 signature, same canonical hashing — so that operator
actions appear in compliance evidence packs alongside agent calls.

This module ships the *interface* + a contract test now so:

  * Phase 5 evidence-pack builders can already filter on
    ``action == "operator.*"`` (the SOC 2, HIPAA, PCI-DSS, GLBA,
    ISO 27001, and FedRAMP modules all do).
  * Phase 6's Console implementation has a typed contract to satisfy
    and a contract test to gate its CI on.

The implementation is *not* part of Phase 5 — the Registry currently
exposes only a stub that raises ``NotImplementedError`` if invoked.

Why a Protocol rather than an abstract base class? We want the Console
implementation to live in its own package without an import dependency
on this one beyond the type signature. ``typing.Protocol`` gives us
structural typing — any class with the right methods satisfies the
contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Protocol, runtime_checkable

from .models import Receipt


@dataclass(frozen=True)
class OperatorAction:
    """Plaintext description of an operator action, before any signing.

    Every field maps 1:1 onto the receipt envelope produced by
    :meth:`OperatorAuditTrail.record_action`.
    """

    operator_did: str
    """The DID of the human operator performing the action. MUST be a
    real, registered DID — anonymous operator actions are never accepted
    in evidence packs."""

    target_did: str
    """The DID the action targets (tenant DID for ``pause_tenant``,
    delegation DID for ``revoke_delegation``, etc)."""

    action: str
    """A capability name in the ``operator.<verb>`` namespace.
    Examples: ``operator.pause_tenant``, ``operator.rotate_did``,
    ``operator.override_policy``."""

    reason: str
    """Free-text human explanation. The Console's UI requires this for
    every operator action and forwards it verbatim."""

    metadata: dict[str, Any]
    """Action-specific structured payload (the new policy version on a
    rotation, the delegation id on a revocation, etc.)."""


@runtime_checkable
class OperatorAuditTrail(Protocol):
    """Protocol implemented by any operator audit-trail backend.

    The Phase 6 Console will provide a concrete implementation backed by
    the Registry's ``/v1/admin/operator_actions`` endpoint (to be added
    in Phase 6); tests use an in-memory stub.
    """

    async def record_action(self, action: OperatorAction) -> Receipt:
        """Sign + persist the action; return the resulting receipt.

        Implementations MUST:

          * canonicalize the envelope via JCS,
          * sign with the operator's Ed25519 key (via the deployer's
            KMS — the Console never touches raw keys),
          * persist via the same Registry path as runtime receipts so
            the result is auto-anchored by the Merkle batcher,
          * return the materialised :class:`Receipt` (with ``leaf_hash``
            populated, ``leaf_index`` typically ``None`` until the next
            anchoring tick).

        Implementations MUST NOT:

          * forge ``executed_at`` timestamps,
          * skip the Registry round-trip (no "fire-and-forget" mode),
          * accept un-DID'd operators.
        """
        ...


# ---------------------------------------------------------------------------
# Contract test (mixin)
# ---------------------------------------------------------------------------


class OperatorAuditTrailContract:
    """Mixin for ``unittest.TestCase`` (or pytest classes) that any
    concrete :class:`OperatorAuditTrail` implementation can subclass to
    inherit a basic contract suite.

    Subclass and set :pyattr:`audit_factory` to a zero-arg async callable
    returning a fresh implementation:

    .. code-block:: python

        class TestMyImpl(OperatorAuditTrailContract, unittest.IsolatedAsyncioTestCase):
            audit_factory = staticmethod(_build_my_impl)

    The contract enforces the minimum behaviour the Console relies on
    and the evidence-pack assembler treats as invariant.
    """

    audit_factory: Callable[[], Awaitable[OperatorAuditTrail]]

    async def _build(self) -> OperatorAuditTrail:
        return await type(self).audit_factory()

    @staticmethod
    def sample_action() -> OperatorAction:
        return OperatorAction(
            operator_did="did:web:example.com:operator:opal",
            target_did="did:web:tenant.example.com",
            action="operator.pause_tenant",
            reason="Investigating elevated 5xx rate in incident #1234",
            metadata={"incident_id": "1234"},
        )

    async def test_records_returns_receipt(self) -> None:
        impl = await self._build()
        receipt = await impl.record_action(self.sample_action())
        # The receipt is the proof object the auditor will inspect.
        assert isinstance(receipt, Receipt)
        assert receipt.action == "operator.pause_tenant"
        assert receipt.iss == "did:web:example.com:operator:opal"
        assert receipt.signature
        assert receipt.executed_at

    async def test_action_namespace(self) -> None:
        impl = await self._build()
        receipt = await impl.record_action(self.sample_action())
        # Evidence-pack filters key off the ``operator.`` prefix; if it
        # ever drifts the SOC2/HIPAA/PCI/GLBA/ISO/FedRAMP packs all break
        # silently.
        assert receipt.action.startswith("operator."), (
            "operator audit-trail receipts MUST use the 'operator.' "
            "capability namespace"
        )


__all__ = [
    "OperatorAction",
    "OperatorAuditTrail",
    "OperatorAuditTrailContract",
]
