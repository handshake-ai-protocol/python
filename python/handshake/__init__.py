"""Handshake protocol — Python SDK.

Thin wrapper over the canonical Rust core (`packages/handshake-rs`) via PyO3.
The cryptographic surface (`canonicalize`, `sha256_hex`, Ed25519, ML-DSA-65)
delegates byte-for-byte to Rust, so this SDK cannot drift from the reference
implementation. Pure-Python helpers live alongside for ergonomics — see
`models` for Pydantic v2 schemas mirroring the v0.2.3 JSON Schemas.

Architecture rationale: docs/decisions/0006-rust-core-authoritative.md
"""

from __future__ import annotations

import json
from typing import Any

from . import _native  # type: ignore[attr-defined]
from . import models
from . import verify as _verify_mod

SPEC_VERSION: str = _native.SPEC_VERSION
__version__: str = _native.__version__

# Re-export the native primitives directly. Callers that want raw byte access
# can call these — but most should use the higher-level helpers below.
sha256 = _native.sha256
sha256_hex = _native.sha256_hex
ed25519_keypair_from_seed = _native.ed25519_keypair_from_seed
ed25519_sign = _native.ed25519_sign
ed25519_verify = _native.ed25519_verify
mldsa65_keypair_from_seed = _native.mldsa65_keypair_from_seed
mldsa65_sign = _native.mldsa65_sign
mldsa65_verify = _native.mldsa65_verify


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 byte representation of `value`.

    Always JSON-encodes `value` first (via `json.dumps`), then hands the text
    to the Rust JCS implementation, which enforces the RFC's key ordering,
    IEEE-754 number form, and string escaping rules. To canonicalize raw JSON
    text instead, decode it once with `json.loads` and pass the result here.

    >>> canonicalize({"b": 2, "a": 1})
    b'{"a":1,"b":2}'
    >>> canonicalize("hello")
    b'"hello"'
    """
    # `separators=(",", ":")` collapses Python's default whitespace; the Rust
    # JCS layer reparses anyway, so this is purely about predictable input
    # length on the FFI hop.
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    out: bytes = _native.canonicalize(text)
    return out


verify_handshake_request = _verify_mod.verify_handshake_request
intersect_capabilities = _verify_mod.intersect_capabilities
VerifyResult = _verify_mod.VerifyResult

# Phase 4 — high-level producer API + KMS abstraction. Imported lazily-named
# (after canonicalize is defined) because client.py imports `canonicalize`
# from this module at import time.
from . import kms  # noqa: E402
from . import client as _client_mod  # noqa: E402

Handshake = _client_mod.Handshake
HandshakeContext = _client_mod.HandshakeContext
RegistryError = _client_mod.RegistryError

__all__ = [
    "SPEC_VERSION",
    "__version__",
    "canonicalize",
    "sha256",
    "sha256_hex",
    "ed25519_keypair_from_seed",
    "ed25519_sign",
    "ed25519_verify",
    "mldsa65_keypair_from_seed",
    "mldsa65_sign",
    "mldsa65_verify",
    "models",
    "verify",
    "verify_handshake_request",
    "intersect_capabilities",
    "VerifyResult",
    # Phase 4 producer surface
    "Handshake",
    "HandshakeContext",
    "RegistryError",
    "kms",
    "client",
]

# Expose submodules under their short names for ergonomic imports.
verify = _verify_mod
client = _client_mod
