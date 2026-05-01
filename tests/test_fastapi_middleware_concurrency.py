"""ROUND-9 audit regression tests for `FastAPIHandshakeMiddleware`.

The Phase-10 follow-up T003 added a Postgres-backed `NonceStore` for
cross-instance replay protection. The store performs SYNCHRONOUS
network I/O via psycopg, but the FastAPI middleware's `__call__` was
calling it directly from inside `async def __call__` — blocking the
asyncio event loop on every request for the duration of the DB
roundtrip (typically tens of ms; up to the full pool-exhaustion
timeout of 30 s under load).

Symptoms in production would have been:

  * Throughput collapsing to "1 request per DB roundtrip per worker".
  * All other coroutines on the worker (health checks, SSE keepalives,
    background heartbeats) starved while the nonce check was outstanding.
  * Tail latency dominated by anyone else's slow DB call.

The fix wraps the call in `asyncio.to_thread(...)` so the sync I/O
runs in the default executor pool and the event loop stays responsive.
The Protocol docstring requires `check_and_record` to be thread-safe,
so worker-thread dispatch is always sound.

These tests verify both:

  1. The call is offloaded (runs in a thread other than the asyncio
     loop's main thread).
  2. Concurrent requests through the middleware no longer serialize on
     a slow store.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from base64 import urlsafe_b64encode
from typing import Any

import pytest

from handshake.middleware.fastapi import FastAPIHandshakeMiddleware, REQUEST_HEADER
from handshake.verify import VerifyResult


def _b64u_envelope(envelope: dict[str, Any]) -> str:
    raw = json.dumps(envelope).encode()
    return urlsafe_b64encode(raw).decode().rstrip("=")


def _scope(envelope_b64u: str) -> dict[str, Any]:
    return {
        "type": "http",
        "headers": [(REQUEST_HEADER.encode(), envelope_b64u.encode())],
    }


async def _drive(mw: FastAPIHandshakeMiddleware, envelope_b64u: str) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []

    async def send(msg: dict[str, Any]) -> None:
        sent.append(msg)

    async def recv() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    await mw(_scope(envelope_b64u), recv, send)
    return sent


class _SleepyReplayStore:
    """A NonceStore that sleeps `sleep_s` seconds in `check_and_record`
    and always returns True (replay). Returning True means the middleware
    rejects the request immediately after the nonce check, which lets
    these tests skip the (heavier) Handshake-context construction path
    that would normally follow.
    """

    def __init__(self, sleep_s: float) -> None:
        self.sleep_s = sleep_s
        self.thread_ids: list[int] = []
        self._lock = threading.Lock()

    def check_and_record(self, nonce: str) -> bool:
        with self._lock:
            self.thread_ids.append(threading.get_ident())
        time.sleep(self.sleep_s)
        return True


def _make_envelope(nonce: str) -> dict[str, Any]:
    return {
        "id": "hsk_round9_test",
        "iss": "did:hsk:caller",
        "aud": "did:hsk:my-service",
        "iat": "2026-01-01T00:00:00Z",
        "exp": "2099-01-01T00:00:00Z",
        "nonce": nonce,
        "capability": {"name": "demo"},
    }


def _bypass_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace `verify_handshake_request` so the nonce check is reached
    without needing real signing keys / signed envelopes. The bug we're
    testing lives entirely in the post-verify nonce-check call site."""
    monkeypatch.setattr(
        "handshake.middleware.fastapi.verify_handshake_request",
        lambda **_kwargs: VerifyResult(accepted=True),
    )


def test_nonce_check_runs_off_the_event_loop_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    """REGRESSION (round-9): the call site must dispatch via
    `asyncio.to_thread`, not invoke the sync store from the event loop.

    We assert the captured thread id inside `check_and_record` is NOT
    the asyncio main thread. With the pre-fix code (direct sync call)
    the captured id WOULD equal the main thread id and this assertion
    would fail.
    """
    _bypass_verify(monkeypatch)
    store = _SleepyReplayStore(sleep_s=0.0)
    mw = FastAPIHandshakeMiddleware(
        app=None,  # not reached: store returns True → reject before app dispatch
        handshake=None,  # not reached either, same reason
        keys={},
        receiver_did="did:hsk:my-service",
        nonce_store=store,
    )

    async def go() -> int:
        loop_thread_id = threading.get_ident()
        await _drive(mw, _b64u_envelope(_make_envelope("nonce-1")))
        return loop_thread_id

    loop_thread_id = asyncio.run(go())
    assert len(store.thread_ids) == 1
    assert store.thread_ids[0] != loop_thread_id, (
        "check_and_record ran on the event-loop thread — slow distributed "
        "stores will block all concurrent requests. Use asyncio.to_thread."
    )


def test_concurrent_requests_dont_serialize_on_slow_nonce_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REGRESSION (round-9): five concurrent requests with a 100ms-sleeping
    nonce store must finish in well under 5 * 100ms = 500ms wall time.
    With the pre-fix code (direct sync call from `async def __call__`),
    they would serialize on the event loop and total time would be
    ~500ms.

    Threshold of 300ms gives generous headroom for thread-pool startup
    and CI noise while still catching event-loop blocking (which would
    push the total to ~500ms+).
    """
    _bypass_verify(monkeypatch)
    sleep_s = 0.1
    store = _SleepyReplayStore(sleep_s=sleep_s)
    mw = FastAPIHandshakeMiddleware(
        app=None,
        handshake=None,
        keys={},
        receiver_did="did:hsk:my-service",
        nonce_store=store,
    )

    async def go() -> float:
        envelopes = [_b64u_envelope(_make_envelope(f"nonce-{i}")) for i in range(5)]
        t0 = time.monotonic()
        await asyncio.gather(*(_drive(mw, e) for e in envelopes))
        return time.monotonic() - t0

    elapsed = asyncio.run(go())

    assert len(store.thread_ids) == 5, "all five requests should reach check_and_record"

    # The serial-execution failure mode would put us at ~5 * 100ms = 500ms.
    # The parallel target is ~100ms (5 threads each doing 100ms in parallel).
    # 300ms cleanly distinguishes the two regimes with CI headroom.
    assert elapsed < 0.30, (
        f"5 concurrent requests with a {sleep_s*1000:.0f}ms nonce store took "
        f"{elapsed*1000:.0f}ms — event loop appears blocked. The fix is to "
        f"call check_and_record via asyncio.to_thread."
    )

    # And — defensively — every call should have run on a worker thread,
    # not the asyncio main thread.
    main = threading.main_thread().ident
    assert all(tid != main for tid in store.thread_ids), (
        "at least one check_and_record ran on the main thread — the offload "
        "is incomplete."
    )
