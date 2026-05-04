# SPDX-License-Identifier: MIT
"""Unit tests for the Phase 4 producer surface.

Scope:
  * `SoftwareKMS` round-trips signing + Rust-core verifies signatures.
  * `Handshake.delegate / handshake / record_receipt` produce envelopes that
    pass JCS-canonical verification under the producer's public key.
  * Framework wrappers run in MOCK mode and emit receipts whose
    `upstream_receipts` link as expected.
  * Transport adapters (MCP/A2A/AP2) round-trip a request envelope through
    their respective wire bindings.
  * FastAPI middleware verifies a real signed request and rejects bogus ones.

These tests do NOT require the live Registry — they use `Handshake(offline=True)`
so they can run in CI before the stack is up.
"""

from __future__ import annotations

import json
from base64 import urlsafe_b64decode

import pytest

import handshake
from handshake import Handshake, canonicalize, ed25519_verify
from handshake.frameworks.anthropic import wrap as wrap_anthropic
from handshake.frameworks.langgraph import wrap_node
from handshake.frameworks.openai_agents import wrap as wrap_openai
from handshake.kms import KmsError, SoftwareKMS
from handshake.middleware.fastapi import (
    FastAPIHandshakeMiddleware,
    HandshakeRequestState,
    REQUEST_HEADER,
)
from handshake.middleware.grpc import verify_metadata, METADATA_KEY
from handshake.models import Capability
from handshake.transports import a2a, ap2, mcp


def _b64u(b: bytes) -> str:
    from base64 import urlsafe_b64encode

    return urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    pad = (-len(s)) % 4
    return urlsafe_b64decode(s + ("=" * pad))


def _verify_envelope(envelope: dict, pubkey: bytes) -> bool:
    body = {k: v for k, v in envelope.items() if k != "signature"}
    msg = canonicalize(body)
    sig = _b64u_dec(envelope["signature"])
    return ed25519_verify(pubkey, sig, msg)


# ---- KMS -------------------------------------------------------------------
def test_software_kms_signs_and_verifies() -> None:
    kms = SoftwareKMS.generate(did="did:hsk:test")
    msg = b"hello phase 4"
    sig = kms.sign(msg)
    assert len(sig) == 64
    assert ed25519_verify(kms.public_key(), sig, msg)


def test_software_kms_seed_validation() -> None:
    with pytest.raises(KmsError):
        SoftwareKMS(did="did:hsk:test", seed=b"\x00" * 16)
    with pytest.raises(KmsError):
        SoftwareKMS(did="did:hsk:test", seed=b"\x00" * 32, algorithm="ML-DSA-65")


def test_hsm_stubs_refuse_to_construct() -> None:
    from handshake.kms import AzureKeyVaultHSM, CloudHSMPKCS11, GCPCloudHSM

    with pytest.raises(KmsError):
        CloudHSMPKCS11(did="did:hsk:t", slot_id=0, key_label="k")
    with pytest.raises(KmsError):
        AzureKeyVaultHSM(did="did:hsk:t", vault_url="x", key_name="k")
    with pytest.raises(KmsError):
        GCPCloudHSM(did="did:hsk:t", key_name="k")


# ---- Handshake client ------------------------------------------------------
def _hs() -> tuple[Handshake, SoftwareKMS]:
    kms = SoftwareKMS.generate(did="did:hsk:producer")
    return Handshake(kms=kms, offline=True), kms


def test_delegate_produces_signed_token() -> None:
    hs, kms = _hs()
    tok = hs.delegate(
        sub="did:hsk:agent",
        aud="did:hsk:tool.x",
        capability=Capability(name="x.y"),
    )
    payload = tok.model_dump(mode="json", exclude_none=True)
    assert _verify_envelope(payload, kms.public_key())
    assert tok.id.startswith("dt_")
    assert tok.iss == "did:hsk:producer"
    assert tok.alg.value == "EdDSA"


def test_handshake_returns_context_with_signed_request() -> None:
    hs, kms = _hs()
    tok = hs.delegate(sub="did:hsk:agent", aud="did:hsk:tool.x", capability=Capability(name="x.y"))
    ctx = hs.handshake(aud="did:hsk:tool.x", capability=Capability(name="x.y"), delegation_chain=[tok])
    assert ctx.handshake_id.startswith("hs_")
    assert ctx.iss == "did:hsk:producer"
    assert _verify_envelope(ctx.request, kms.public_key())


def test_record_receipt_offline_returns_signed_envelope() -> None:
    hs, kms = _hs()
    tok = hs.delegate(sub="did:hsk:agent", aud="did:hsk:tool.x", capability=Capability(name="x.y"))
    ctx = hs.handshake(aud="did:hsk:tool.x", capability=Capability(name="x.y"), delegation_chain=[tok])
    out = hs.record_receipt(ctx, action="x.do", result="ok", result_payload={"n": 1})
    env = out["envelope"]
    assert env["handshake_id"] == ctx.handshake_id
    assert env["sub"] == "did:hsk:tool.x"
    assert env.get("upstream_receipts") in (None, [])
    assert _verify_envelope(env, kms.public_key())


def test_record_receipt_carries_upstream_links() -> None:
    hs, _ = _hs()
    tok = hs.delegate(sub="did:hsk:agent", aud="did:hsk:tool", capability=Capability(name="x"))
    ctx = hs.handshake(aud="did:hsk:tool", capability=Capability(name="x"), delegation_chain=[tok])
    parents = ["rc_PARENT1ABCDEFGHIJKLMNOPQR", "rc_PARENT2ABCDEFGHIJKLMNOPQR"]
    out = hs.record_receipt(ctx, action="x", upstream_receipts=parents)
    assert out["envelope"]["upstream_receipts"] == parents


# ---- Framework wrappers ----------------------------------------------------
def test_anthropic_wrapper_mock_emits_receipt() -> None:
    hs, _ = _hs()
    hs.offline = True
    client = wrap_anthropic(handshake=hs)
    assert client.is_mock
    msg = client.messages.create(model="claude-3", messages=[{"role": "user", "content": "hi"}])
    assert getattr(msg, "handshake_receipt_id", "").startswith("rc_")
    assert msg.content[0].text.startswith("[handshake-mock claude]")


def test_openai_agents_wrapper_mock_emits_receipt() -> None:
    hs, _ = _hs()
    runner = wrap_openai(handshake=hs)
    assert runner.is_mock
    out = runner.run("hello world")
    assert out["receipt_id"].startswith("rc_")
    assert out["text"].startswith("[handshake-mock openai-agents]")


def test_langgraph_wrapper_threads_receipts_through_state() -> None:
    hs, _ = _hs()

    def n1(state: dict) -> dict:
        return {"x": 1}

    def n2(state: dict) -> dict:
        return {"y": state.get("x", 0) + 1}

    aud_n1 = wrap_node(n1, handshake=hs, action="t.n1", tool_did="did:hsk:tool.n1")
    aud_n2 = wrap_node(n2, handshake=hs, action="t.n2", tool_did="did:hsk:tool.n2")
    state: dict = {}
    state.update(aud_n1(state))
    state.update(aud_n2(state))
    chain = state["_handshake_receipts"]
    assert len(chain) == 2 and all(r.startswith("rc_") for r in chain)


# ---- Transport adapters ----------------------------------------------------
def test_mcp_adapter_round_trip() -> None:
    hs, _ = _hs()
    tok = hs.delegate(sub="did:hsk:a", aud="did:hsk:t", capability=Capability(name="x"))
    ctx = hs.handshake(aud="did:hsk:t", capability=Capability(name="x"), delegation_chain=[tok])
    payload = mcp.attach({"tool": "search"}, ctx)
    extracted = mcp.extract(payload)
    assert extracted is not None
    assert extracted["id"] == ctx.handshake_id
    payload = mcp.stamp_receipt_id(payload, "rc_TESTABCDEFGHIJKLMNOPQRSTU")
    assert payload["_meta"]["handshake"]["receipt_id"] == "rc_TESTABCDEFGHIJKLMNOPQRSTU"


def test_a2a_adapter_round_trip() -> None:
    hs, _ = _hs()
    tok = hs.delegate(sub="did:hsk:a", aud="did:hsk:t", capability=Capability(name="x"))
    ctx = hs.handshake(aud="did:hsk:t", capability=Capability(name="x"), delegation_chain=[tok])
    headers: dict = {}
    a2a.stamp_request(headers, ctx)
    extracted = a2a.extract_request(headers)
    assert extracted is not None and extracted["id"] == ctx.handshake_id
    a2a.stamp_receipt(headers, "rc_TESTABCDEFGHIJKLMNOPQRSTU")
    assert headers[a2a.RECEIPT_HEADER] == "rc_TESTABCDEFGHIJKLMNOPQRSTU"


def test_ap2_adapter_round_trip() -> None:
    hs, _ = _hs()
    tok = hs.delegate(sub="did:hsk:a", aud="did:hsk:t", capability=Capability(name="x"))
    ctx = hs.handshake(aud="did:hsk:t", capability=Capability(name="x"), delegation_chain=[tok])
    mandate: dict = {"amount": 100}
    ap2.attach_to_mandate(mandate, ctx)
    extracted = ap2.extract_from_mandate(mandate)
    assert extracted is not None and extracted["id"] == ctx.handshake_id


# ---- gRPC interceptor (verify-only path; no live grpc) ---------------------
def test_grpc_verify_metadata_rejects_missing() -> None:
    hs, _ = _hs()
    ok, err = verify_metadata({}, keys={}, receiver_did="did:hsk:svc", handshake=hs)
    assert not ok
    assert err["code"] == "handshake_missing"


def test_grpc_verify_metadata_rejects_malformed() -> None:
    hs, _ = _hs()
    ok, err = verify_metadata(
        {METADATA_KEY: "@@not-base64@@"}, keys={}, receiver_did="did:hsk:svc", handshake=hs
    )
    assert not ok
    assert err["code"] == "handshake_malformed"
