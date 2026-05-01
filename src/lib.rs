//! PyO3 FFI shim — Python bindings for the canonical Rust Handshake core.
//!
//! Every cryptographic function here forwards directly into the `handshake`
//! crate (sibling path-dep on `packages/handshake-rs`). Python callers cannot
//! observe a different result than Rust callers, by construction; that is the
//! whole point of the FFI architecture (ADR-0006).
//!
//! Module entry point: `_native`. `pyproject.toml` declares the importable
//! Python module as `handshake._native`, and the Rust `[lib].name` is
//! `handshake_py` (drives the `.so` filename); maturin assembles the wheel so
//! `import handshake._native` resolves to the `PyInit__native` symbol below.

use std::collections::HashMap;

use handshake::verify::{intersect_to_json_string, verify_to_json_string};
use handshake::{hash, jcs, mldsa, sign};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyTuple};

/// JCS-canonicalize a JSON document supplied as a UTF-8 string.
///
/// We require pre-serialized JSON text (rather than accepting arbitrary Python
/// objects) so the FFI hop is unambiguous and the Python caller sees the same
/// behavior the TypeScript caller does. The high-level `handshake.canonicalize`
/// wrapper in `python/handshake/__init__.py` calls `json.dumps` first.
#[pyfunction]
fn canonicalize(py: Python<'_>, text: &str) -> PyResult<Py<PyBytes>> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| PyValueError::new_err(format!("invalid JSON: {e}")))?;
    let bytes = jcs::canonicalize(&value)
        .map_err(|e| PyValueError::new_err(format!("canonicalize: {e}")))?;
    Ok(PyBytes::new(py, &bytes).into())
}

/// Raw 32-byte SHA-256 digest of `data`.
#[pyfunction]
fn sha256(py: Python<'_>, data: &[u8]) -> Py<PyBytes> {
    PyBytes::new(py, &hash::sha256(data)).into()
}

/// Lowercase-hex SHA-256 digest of `data`.
#[pyfunction]
fn sha256_hex(data: &[u8]) -> String {
    hash::sha256_hex(data)
}

fn seed_array(seed: &[u8]) -> PyResult<[u8; 32]> {
    seed.try_into().map_err(|_| {
        PyValueError::new_err(format!("expected 32-byte seed, got {} bytes", seed.len()))
    })
}

/// Ed25519 keypair from a 32-byte seed (RFC 8032 §5.1.5).
///
/// Returns `(seed_bytes, public_key_bytes)`. The seed is round-tripped so
/// callers can persist it without holding the original buffer.
#[pyfunction]
fn ed25519_keypair_from_seed(py: Python<'_>, seed: &[u8]) -> PyResult<Py<PyTuple>> {
    let seed = seed_array(seed)?;
    let kp = sign::Keypair::from_seed(&seed);
    let elements = [
        PyBytes::new(py, &kp.seed()).into_any(),
        PyBytes::new(py, &kp.public_key()).into_any(),
    ];
    Ok(PyTuple::new(py, elements)?.into())
}

/// Ed25519 sign — returns the raw 64-byte signature.
#[pyfunction]
fn ed25519_sign(py: Python<'_>, seed: &[u8], message: &[u8]) -> PyResult<Py<PyBytes>> {
    let seed = seed_array(seed)?;
    let kp = sign::Keypair::from_seed(&seed);
    Ok(PyBytes::new(py, &kp.sign(message)).into())
}

/// Ed25519 verify. Returns `True` on a valid signature, `False` otherwise.
/// Length errors raise `ValueError` since they indicate a caller bug rather
/// than a forgery.
#[pyfunction]
fn ed25519_verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> PyResult<bool> {
    if public_key.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "expected 32-byte public key, got {}",
            public_key.len()
        )));
    }
    if signature.len() != 64 {
        return Err(PyValueError::new_err(format!(
            "expected 64-byte signature, got {}",
            signature.len()
        )));
    }
    Ok(sign::verify(public_key, signature, message).is_ok())
}

/// ML-DSA-65 (FIPS 204) keypair from a 32-byte seed.
///
/// Returns `(private_key_bytes, public_key_bytes)`. Sizes:
/// private = [`mldsa::PRIVATE_KEY_LEN`] = 4032, public = [`mldsa::PUBLIC_KEY_LEN`] = 1952.
#[pyfunction]
fn mldsa65_keypair_from_seed(py: Python<'_>, seed: &[u8]) -> PyResult<Py<PyTuple>> {
    let seed = seed_array(seed)?;
    let kp = mldsa::Keypair::from_seed(&seed);
    let elements = [
        PyBytes::new(py, &kp.private_key()).into_any(),
        PyBytes::new(py, &kp.public_key()).into_any(),
    ];
    Ok(PyTuple::new(py, elements)?.into())
}

/// ML-DSA-65 deterministic sign — returns the raw 3309-byte signature.
///
/// We accept the seed (not the pre-derived private key) so the FFI surface is
/// uniform with the Ed25519 helpers and so the Go runner — which also takes a
/// seed — has an identical call shape. Determinism is enforced by
/// `Keypair::sign` calling the FIPS 204 §5.5 deterministic variant.
#[pyfunction]
fn mldsa65_sign(py: Python<'_>, seed: &[u8], message: &[u8]) -> PyResult<Py<PyBytes>> {
    let seed = seed_array(seed)?;
    let kp = mldsa::Keypair::from_seed(&seed);
    Ok(PyBytes::new(py, &kp.sign(message)).into())
}

/// ML-DSA-65 verify. Returns `True` on a valid signature, `False` otherwise.
/// Wrong-length keys / signatures raise `ValueError`.
#[pyfunction]
fn mldsa65_verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> PyResult<bool> {
    if public_key.len() != mldsa::PUBLIC_KEY_LEN {
        return Err(PyValueError::new_err(format!(
            "expected {}-byte ML-DSA-65 public key, got {}",
            mldsa::PUBLIC_KEY_LEN,
            public_key.len()
        )));
    }
    if signature.len() != mldsa::SIGNATURE_LEN {
        return Err(PyValueError::new_err(format!(
            "expected {}-byte ML-DSA-65 signature, got {}",
            mldsa::SIGNATURE_LEN,
            signature.len()
        )));
    }
    match mldsa::verify(public_key, signature, message) {
        Ok(()) => Ok(true),
        Err(handshake::Error::SignatureInvalid(_)) => Ok(false),
        Err(other) => Err(PyTypeError::new_err(other.to_string())),
    }
}

/// Verify a `HandshakeRequest` (JSON string) against the Phase 2 chain-walk
/// verifier. The `keys` dict maps DID → 32-byte raw Ed25519 public key. The
/// returned JSON string carries either `{result:"accept", ...}` or
/// `{result:"reject", error_code, rejected_at_step, detail, rejected_delegation_id}`.
///
/// This is the FFI-level API; `handshake.verify.verify_handshake_request`
/// in Python wraps it for ergonomic dict-of-bytes / list-of-str input.
#[pyfunction]
#[pyo3(signature = (request_json, keys, receiver_did, now_rfc3339, revoked_principals = None, revoked_delegations = None))]
fn verify_handshake_request_json(
    request_json: &str,
    keys: &Bound<'_, PyDict>,
    receiver_did: &str,
    now_rfc3339: &str,
    revoked_principals: Option<Vec<String>>,
    revoked_delegations: Option<Vec<String>>,
) -> PyResult<String> {
    let mut key_map: HashMap<String, [u8; 32]> = HashMap::new();
    for (k, v) in keys.iter() {
        let did: String = k.extract()?;
        let bytes: Vec<u8> = v.extract()?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            PyValueError::new_err(format!(
                "key for DID {did}: expected 32-byte Ed25519 public key, got {} bytes",
                bytes.len()
            ))
        })?;
        key_map.insert(did, arr);
    }
    let revoked_principals = revoked_principals.unwrap_or_default();
    let revoked_delegations = revoked_delegations.unwrap_or_default();
    verify_to_json_string(
        request_json,
        &key_map,
        receiver_did,
        now_rfc3339,
        &revoked_principals,
        &revoked_delegations,
    )
    .map_err(|e| PyValueError::new_err(format!("verify failed: {e}")))
}

/// Intersect two capability constraint sets supplied as JSON object strings.
/// Returns a JSON string per the Rust core's `intersect_to_json_string`.
#[pyfunction]
fn intersect_capabilities_json(delegated_json: &str, requested_json: &str) -> PyResult<String> {
    intersect_to_json_string(delegated_json, requested_json)
        .map_err(|e| PyValueError::new_err(format!("intersect failed: {e}")))
}

/// PyO3 module entry point. Module name MUST be `_native` so the generated
/// `PyInit__native` symbol matches the Python import path
/// `handshake._native` declared in `pyproject.toml`.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SPEC_VERSION", handshake::SPEC_VERSION)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(canonicalize, m)?)?;
    m.add_function(wrap_pyfunction!(sha256, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_hex, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_keypair_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_verify, m)?)?;
    m.add_function(wrap_pyfunction!(mldsa65_keypair_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(mldsa65_sign, m)?)?;
    m.add_function(wrap_pyfunction!(mldsa65_verify, m)?)?;
    m.add_function(wrap_pyfunction!(verify_handshake_request_json, m)?)?;
    m.add_function(wrap_pyfunction!(intersect_capabilities_json, m)?)?;
    Ok(())
}
