"""Signing-key management — `KeyManagementProvider` Protocol + backends.

Phase 4 introduces a signing-key abstraction that mirrors the
`KeyManagementProvider` already used by the Registry for data-at-rest DEK
wrapping (apps/handshake-registry/.../kms/base.py). The two are intentionally
separate Protocols because the trust model differs: a DEK provider holds AEAD
keys derived from a KEK; a *signing* provider holds long-lived asymmetric
private keys whose public half is published in DID Documents.

Why this lives in the SDK and not the Registry:
  * Producers (the agents emitting receipts) sign locally — they do NOT call
    the Registry to sign. Wiring KMS into the SDK lets every framework wrapper
    (Anthropic, OpenAI Agents, LangGraph, …) get HSM swap-out for free, just
    by passing a different provider into `Handshake(kms=...)`.
  * Test/CI runs use `SoftwareKMS` (libsodium in-process, deterministic for
    tests). Production deployments swap in `CloudHSMPKCS11`,
    `AzureKeyVaultHSM`, or `GCPCloudHSM` (stubs in this module — wiring them
    is environment-specific and out of scope for Phase 4).

Architecture: ADR-0011 (`docs/decisions/0011-kms-in-sdk.md`).
"""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

from . import _native  # type: ignore[attr-defined]


class KmsError(Exception):
    """Raised by any signing KMS provider on key-not-found / sign failure.

    Distinct from the Registry's `kms.base.KmsError` because callers may want
    to catch SDK-side signing errors without pulling in Registry internals.
    """


@runtime_checkable
class KeyManagementProvider(Protocol):
    """Holds a Handshake producer's private key and signs envelopes.

    Implementations MUST guarantee:
      * `public_key()` returns the raw public key bytes (32 bytes for Ed25519,
        1952 bytes for ML-DSA-65) — the same bytes the Registry stores as
        `primary_ed25519_pubkey_b64u` on the DID record.
      * `sign(message)` produces a signature byte-for-byte verifiable under
        the corresponding public key by `ed25519_verify` / `mldsa65_verify`
        in the canonical Rust core.
      * Raw private key bytes NEVER leave the provider (HSM-style
        invariant) — software providers may relax this internally but MUST
        NOT expose accessor methods.

    `did` is the producer DID this key represents. Wrappers use it to set
    `iss` on outgoing envelopes without the caller having to thread it
    through manually.
    """

    name: str
    did: str

    def algorithm(self) -> str:
        """One of `EdDSA`, `ML-DSA-65`, `Hybrid-EdDSA-MLDSA65`."""
        ...

    def public_key(self) -> bytes:
        """Raw public key bytes (no multibase prefix)."""
        ...

    def sign(self, message: bytes) -> bytes:
        """Produce a signature over `message`. Caller is responsible for any
        canonicalization (this method signs raw bytes verbatim)."""
        ...


class SoftwareKMS:
    """In-process libsodium signer. The default for tests, examples, and
    development. Holds the secret key in process memory — adequate for CI,
    NOT for production agents handling real-money capabilities (use one of
    the HSM stubs below).

    Construct from a 32-byte Ed25519 seed (`from_seed`) or a freshly
    generated key (`generate`). Both routes derive the public key via the
    canonical Rust core, so SDK-signed envelopes verify identically under
    `ed25519_verify` (Rust), `nacl.signing.VerifyKey.verify` (PyNaCl), and
    OpenSSL.
    """

    name = "software"

    def __init__(self, *, did: str, seed: bytes, algorithm: str = "EdDSA") -> None:
        if algorithm != "EdDSA":
            # Phase 4 ships EdDSA only on the SoftwareKMS hot path; ML-DSA-65
            # is wired into the canonical core but not yet plumbed through
            # the wrapper API (see Phase 9: PQ migration runbook).
            raise KmsError(f"SoftwareKMS only supports EdDSA in Phase 4 (got {algorithm!r})")
        if len(seed) != 32:
            raise KmsError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")
        self.did = did
        self._algorithm = algorithm
        # `_native.ed25519_keypair_from_seed` returns `(seed_bytes, pubkey_bytes)`
        # (see packages/handshake-py/src/lib.rs::ed25519_keypair_from_seed).
        # The Rust signing API takes the SEED, not an expanded secret key, so
        # we keep the seed verbatim and use it for both `sign` and round-trip.
        self._seed, self._public = _native.ed25519_keypair_from_seed(seed)

    @classmethod
    def generate(cls, *, did: str) -> "SoftwareKMS":
        """Create a new keypair from a CSPRNG seed."""
        return cls(did=did, seed=os.urandom(32))

    @classmethod
    def from_seed(cls, *, did: str, seed: bytes) -> "SoftwareKMS":
        return cls(did=did, seed=seed)

    def algorithm(self) -> str:
        return self._algorithm

    def public_key(self) -> bytes:
        return bytes(self._public)

    def sign(self, message: bytes) -> bytes:
        return bytes(_native.ed25519_sign(self._seed, message))


class CloudHSMPKCS11:
    """AWS CloudHSM (PKCS#11) signer — STUB.

    Wiring requires a live CloudHSM cluster, an attached IAM role, and the
    `python-pkcs11` runtime; instantiating this class in any environment
    raises `KmsError`. Production deployments should provide a concrete
    implementation conforming to the `KeyManagementProvider` Protocol; the
    stub exists so `from handshake.kms import CloudHSMPKCS11` resolves and
    ADR-0011 has a one-line migration target.
    """

    name = "aws-cloudhsm"

    def __init__(self, *, did: str, slot_id: int, key_label: str) -> None:
        raise KmsError(
            "CloudHSMPKCS11 is a Phase 4 stub — wire a real PKCS#11 backend "
            "before constructing. See docs/decisions/0011-kms-in-sdk.md."
        )


class AzureKeyVaultHSM:
    """Azure Key Vault (managed HSM) signer — STUB. See `CloudHSMPKCS11`."""

    name = "azure-keyvault-hsm"

    def __init__(self, *, did: str, vault_url: str, key_name: str) -> None:
        raise KmsError(
            "AzureKeyVaultHSM is a Phase 4 stub — wire azure-identity + "
            "azure-keyvault-keys before constructing."
        )


class GCPCloudHSM:
    """GCP Cloud HSM signer — STUB. See `CloudHSMPKCS11`."""

    name = "gcp-cloud-hsm"

    def __init__(self, *, did: str, key_name: str) -> None:
        raise KmsError(
            "GCPCloudHSM is a Phase 4 stub — wire google-cloud-kms before "
            "constructing."
        )


__all__ = [
    "KeyManagementProvider",
    "KmsError",
    "SoftwareKMS",
    "CloudHSMPKCS11",
    "AzureKeyVaultHSM",
    "GCPCloudHSM",
]
