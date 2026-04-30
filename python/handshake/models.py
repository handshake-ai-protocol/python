"""Pydantic v2 models mirroring the v0.2.3 JSON Schemas.

Each model carries enough validation metadata that round-tripping a payload
through it (parse → serialize → canonicalize) reproduces the bytes the
Rust/Go cores produce from the raw JSON. A planned conformance step compares
each model's `model_json_schema()` output against the on-disk JSON Schema
file — drift fails CI.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class SignatureAlgorithm(str, Enum):
    """`_common.json#/$defs/signatureAlgorithm`"""

    ED_DSA = "EdDSA"
    ML_DSA_65 = "ML-DSA-65"
    HYBRID_ED_DSA_ML_DSA_65 = "Hybrid-EdDSA-MLDSA65"


class HashAlgorithm(str, Enum):
    """`_common.json#/$defs/hashAlgorithm`"""

    SHA_256 = "sha-256"
    SHA3_256 = "sha3-256"


class HashValue(BaseModel):
    """`_common.json#/$defs/hashValue`"""

    model_config = ConfigDict(extra="forbid")

    alg: HashAlgorithm
    value: str = Field(description="Lowercase hex digest")


class Capability(BaseModel):
    """`_common.json#/$defs/capability`"""

    model_config = ConfigDict(extra="forbid")

    name: str
    constraints: Optional[Any] = None
    delegable: Optional[bool] = None


class DelegationToken(BaseModel):
    """`delegation-token.json`"""

    model_config = ConfigDict(extra="forbid")

    version: str
    kind: str = Field(pattern=r"^DelegationToken$")
    id: str
    iss: str
    sub: str
    aud: str
    iat: str
    nbf: str
    exp: str
    capabilities: list[Capability] = Field(min_length=1)
    sub_delegation_depth_remaining: int = Field(ge=0)
    parent_delegation_id: Optional[str] = None
    alg: SignatureAlgorithm
    signature: Optional[str] = None


class HandshakeRequest(BaseModel):
    """`handshake-request.json`"""

    model_config = ConfigDict(extra="forbid")

    version: str
    kind: str = Field(pattern=r"^HandshakeRequest$")
    id: str
    iss: str
    aud: str
    iat: str
    nonce: str
    agent_attestation: Any
    capability: Capability
    delegation_chain: list[DelegationToken]
    alg: SignatureAlgorithm
    signature: Optional[str] = None


class ReceiptResult(str, Enum):
    OK = "ok"
    ERROR = "error"
    PARTIAL = "partial"


class Receipt(BaseModel):
    """`receipt.json`"""

    model_config = ConfigDict(extra="forbid")

    version: str
    kind: str = Field(pattern=r"^Receipt$")
    id: str
    handshake_id: str
    iss: str
    sub: str
    action: str
    executed_at: str
    result: ReceiptResult
    result_hash: HashValue
    result_summary: Optional[Any] = None
    upstream_receipts: Optional[list[str]] = None
    registry_anchor: Optional[Any] = None
    alg: SignatureAlgorithm
    signature: Optional[str] = None


__all__ = [
    "SignatureAlgorithm",
    "HashAlgorithm",
    "HashValue",
    "Capability",
    "DelegationToken",
    "HandshakeRequest",
    "ReceiptResult",
    "Receipt",
]
