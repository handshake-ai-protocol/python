# handshake (Python)

Python SDK for the Handshake protocol. **Thin PyO3 wrapper** over the canonical
Rust core (`packages/handshake-rs`). The cryptographic surface delegates
byte-for-byte to Rust, so this SDK cannot drift from the reference
implementation.

## Install (development)

```bash
pip install maturin
cd packages/handshake-py
maturin develop --release
```

`maturin develop` builds the Rust extension and installs `handshake` into the
active Python environment. After that:

```python
import handshake

handshake.canonicalize({"b": 2, "a": 1})  # b'{"a":1,"b":2}'
handshake.sha256_hex(b"hello")            # '2cf24dba...'

# Models mirror the v0.2.3 JSON Schemas
from handshake.models import DelegationToken, SignatureAlgorithm
```

## Architecture

See `docs/decisions/0006-rust-core-authoritative.md` for why Python ships as an
FFI shim rather than a parallel pure-Python implementation. Conformance against
the Rust+Go cores is enforced by `tests/conformance/` — every primitive
exposed here is byte-tested for equality with the other implementations.
