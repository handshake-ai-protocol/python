# SPDX-License-Identifier: MIT
"""PostgreSQL-backed `NonceStore` (Phase 10 follow-up #10).

Implements the :class:`handshake.middleware.grpc.NonceStore` Protocol
(also satisfied by the FastAPI middleware) using a single-statement
upsert on a dedicated `handshake_nonces` table.

Schema (created by Registry migration `0004_handshake_nonces.py`)::

    handshake_nonces (
        nonce       TEXT PRIMARY KEY,
        expires_at  TIMESTAMPTZ NOT NULL
    );
    INDEX idx_handshake_nonces_expires_at ON handshake_nonces (expires_at);

Why a single statement matters
------------------------------

The naive sequence "SELECT then INSERT if not present" is racy across
processes — two concurrent workers can both observe a missing row and
both then INSERT, with one losing on the unique constraint and the
other succeeding. We use::

    INSERT INTO handshake_nonces (nonce, expires_at) VALUES (%s, %s)
        ON CONFLICT (nonce) DO NOTHING
        RETURNING 1

If the row was inserted, the statement returns one row → first sight,
return ``False`` (not a replay). If the conflict path was taken, no
rows are returned → replay, return ``True``. This is atomic at the
SQL level and correct under concurrent access from any number of
pods/workers.

Pruning
-------

Every call has a small (default 1%) chance of issuing
``DELETE FROM handshake_nonces WHERE expires_at < NOW()``. This keeps
the table bounded without requiring an external cron. The TTL is the
freshness window of the verifier: after ``ttl_seconds`` a nonce is no
longer protected by the freshness check anyway, so re-using it would
be rejected on `iat` grounds before reaching this store.

Wire-up example
---------------

Drop-in replacement for the in-memory store, on either FastAPI or
gRPC interceptor::

    import psycopg
    from handshake.middleware.fastapi import HandshakeMiddleware
    from handshake.middleware.nonce_store_pg import PostgresNonceStore

    nonce_store = PostgresNonceStore(
        dsn="postgresql://app:secret@db.internal/handshake",
        ttl_seconds=300,
    )
    app.add_middleware(
        HandshakeMiddleware,
        handshake=Handshake(...),
        keys={...},
        receiver_did="did:hsk:my-service",
        nonce_store=nonce_store,
    )

The implementation uses **psycopg v3** (already a direct dependency of
``handshake-registry``); a small connection pool is created on first use
to keep per-call overhead low.
"""

from __future__ import annotations

import random
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    # psycopg_pool is an optional runtime dep — we don't want to force it
    # on users who never construct a PostgresNonceStore. The TYPE_CHECKING
    # block lets mypy/IDE see ConnectionPool without making it an
    # import-time requirement.
    from psycopg_pool import ConnectionPool


# Identifier validation for the table name. The default is safe; we
# only need this for the (unusual) case where a deployment chose a
# non-default table name. SQL identifiers can't be parameterized so we
# must interpolate, and interpolating unvalidated input is exactly the
# pattern Semgrep's `sqlalchemy-execute-raw-query` rule catches.
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


class PostgresNonceStore:
    """Cross-pod, durable replay protection backed by Postgres.

    Implements ``NonceStore`` Protocol (``check_and_record(nonce) -> bool``).
    Returns ``True`` if the nonce was already seen (replay), else records
    and returns ``False``.

    Thread-safe via psycopg's built-in connection pool.

    Parameters
    ----------
    dsn:
        Postgres connection string, e.g.
        ``postgresql://user:pw@host:5432/dbname``.
    ttl_seconds:
        How long each nonce is retained. Should match the verifier's
        freshness window (default 300 s = 5 min — see
        ``handshake.verify`` defaults).
    table:
        Override the table name. Default ``handshake_nonces`` matches
        Registry migration 0004. Validated against the same regex used
        for SQL identifier interpolation in the Registry migrations.
    pool_min_size, pool_max_size:
        Bounds for the underlying psycopg ConnectionPool.
    prune_probability:
        Probability (0.0–1.0) that a given call also runs an opportunistic
        ``DELETE WHERE expires_at < NOW()``. Default 0.01 → roughly one
        prune per 100 inserts. Set to 0.0 to disable (e.g. when an
        external cron handles pruning).
    """

    def __init__(
        self,
        dsn: str,
        *,
        ttl_seconds: int = 300,
        table: str = "handshake_nonces",
        pool_min_size: int = 1,
        pool_max_size: int = 10,
        prune_probability: float = 0.01,
    ) -> None:
        if not _IDENT_RE.match(table):
            raise ValueError(
                f"table={table!r} is not a valid PostgreSQL identifier"
            )
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if not (0.0 <= prune_probability <= 1.0):
            raise ValueError("prune_probability must be in [0.0, 1.0]")

        self._dsn = dsn
        self._table = table
        self._ttl_seconds = ttl_seconds
        self._pool_min = pool_min_size
        self._pool_max = pool_max_size
        self._prune_probability = prune_probability

        # Lazy pool init so importing this module doesn't fail when
        # psycopg is not installed (the constructor still requires it,
        # but tests can monkeypatch `_get_pool` to inject a fake).
        self._pool: Optional["ConnectionPool"] = None
        self._pool_lock = threading.Lock()

    # --- internals ---

    def _get_pool(self) -> "ConnectionPool":
        if self._pool is not None:
            return self._pool
        with self._pool_lock:
            if self._pool is not None:
                return self._pool
            # Imported lazily to keep psycopg an optional dep.
            from psycopg_pool import ConnectionPool  # type: ignore[import-not-found]

            self._pool = ConnectionPool(
                conninfo=self._dsn,
                min_size=self._pool_min,
                max_size=self._pool_max,
                open=True,
            )
            return self._pool

    def _execute_check(self, nonce: str, expires_at: datetime) -> bool:
        """Run the upsert; return True iff the row already existed (replay)."""
        # Identifier (`self._table`) was regex-validated in __init__.
        # Values (`nonce`, `expires_at`) flow through bound parameters.
        sql = (
            f"INSERT INTO {self._table} (nonce, expires_at) VALUES (%s, %s) "
            f"ON CONFLICT (nonce) DO NOTHING RETURNING 1"
        )
        pool = self._get_pool()
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (nonce, expires_at))
                row = cur.fetchone()
        # row is not None → we inserted (first sight). row is None →
        # ON CONFLICT DO NOTHING was taken (replay).
        return row is None

    def _maybe_prune(self) -> None:
        if self._prune_probability <= 0.0:
            return
        if random.random() >= self._prune_probability:
            return
        sql = f"DELETE FROM {self._table} WHERE expires_at < NOW()"
        try:
            pool = self._get_pool()
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql)
        except Exception:
            # Pruning is best-effort — never let a transient DB error
            # break replay protection on the hot path.
            pass

    # --- Protocol ---

    def check_and_record(self, nonce: str) -> bool:
        """Return ``True`` if *nonce* is a replay; else record it and return ``False``."""
        if not isinstance(nonce, str) or not nonce:
            # Defensive: an empty nonce is meaningless and would let
            # an attacker get past replay detection by sending "".
            # Surface as a replay so the caller rejects the request.
            return True
        expires_at = datetime.now(tz=timezone.utc) + timedelta(seconds=self._ttl_seconds)
        replay = self._execute_check(nonce, expires_at)
        self._maybe_prune()
        return replay

    def close(self) -> None:
        """Close the underlying connection pool. Safe to call multiple times."""
        with self._pool_lock:
            if self._pool is not None:
                try:
                    self._pool.close()
                finally:
                    self._pool = None


__all__ = ["PostgresNonceStore"]
