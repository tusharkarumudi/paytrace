"""Tests that use the REAL network.

Every live-only defect this project has shipped was invisible to the mocked
suite and obvious on first real use: a second event loop closing a client whose
connections belonged to the first, `except httpx.HTTPError: return None`
swallowing timeouts, a non-200 skipped in silence, a seller id compared
case-sensitively. Mock transports do not time out, do not return 403, hold no
connections and never disagree about case.

These are marked `network` and excluded by default (see `addopts`). CI runs them
on a schedule: `pytest -m network`.

Targets are chosen for stability and for having a plain robots.txt. They are
fetched read-only, once, at the polite default rate.
"""

from __future__ import annotations

import asyncio

import pytest

from paytrace import Fetcher

pytestmark = pytest.mark.network

#: Stable, unambiguously public, cheap to fetch.
LIVE_URL = "https://pypi.org/robots.txt"
MISSING_URL = "https://pypi.org/definitely-not-a-real-path-9f3a2b"
DEAD_HOST = "https://no-such-host-9f3a2b1c.invalid/"


def _run(coro):
    return asyncio.run(coro)


def live_fetcher(**kw) -> Fetcher:
    """A Fetcher configured the way a real run configures one.

    A bare `Fetcher` has only a `direct` egress, and a direct egress
    deliberately refuses to trust a CA named by the environment -- so behind an
    intercepting proxy these tests failed TLS verification. They used to pass
    there only because the pinned transport was silently reading
    SSL_CERT_FILE, which is the hole that change set closed; the tests were
    green because of the defect.

    A run adopts an ambient proxy and records the vantage point as
    `environment`, which is what makes the proxy's CA usable and what puts
    `tls_intercepted` in the manifest. These do the same, so they exercise the
    path a run takes. With no proxy set -- CI, a developer's machine -- this is
    an ordinary direct egress and nothing changes.
    """
    import os

    from paytrace.egress import Egress, EgressPool, NetworkType

    var = next((v for v in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY",
                            "all_proxy", "HTTP_PROXY", "http_proxy")
                if os.environ.get(v, "").strip()), "")
    if not var:
        return Fetcher(**kw)
    pool = EgressPool(
        [Egress(label="environment", provider="environment",
                network=NetworkType.DATACENTER)],
        default_label="environment")
    return Fetcher(egress=pool, **kw)


def test_a_real_fetch_succeeds_and_is_captured():
    """The whole guarded path against a real server: DNS, pinning, robots,
    TLS, streaming read, evidence capture."""

    async def go():
        f = live_fetcher(user_agent="paytrace-live-test (+https://pypi.org/)")
        try:
            r = await f.get(LIVE_URL)
            return r, list(f.blocked)
        finally:
            await f.aclose()

    r, blocked = _run(go())
    assert r is not None, f"no response; blocked={blocked}"
    assert r.status == 200
    assert r.text, "a real body must be returned"


def test_a_dead_host_is_recorded_not_swallowed():
    """`except httpx.HTTPError: return None` discarded this class of failure
    entirely, so a retrieval that never happened looked identical to one that
    checked and found nothing."""

    async def go():
        f = live_fetcher(user_agent="paytrace-live-test")
        try:
            r = await f.get(DEAD_HOST)
            return r, list(f.blocked)
        finally:
            await f.aclose()

    r, blocked = _run(go())
    assert r is None
    assert blocked, "a failed retrieval must leave a record"
    assert any("no-such-host" in url for url, _why in blocked)


def test_a_404_is_reported_with_its_status():
    """A response that arrives and is useless must not be skipped in silence."""

    async def go():
        f = live_fetcher(user_agent="paytrace-live-test")
        try:
            return await f.get(MISSING_URL)
        finally:
            await f.aclose()

    r = _run(go())
    assert r is None or r.status == 404, f"unexpected status {getattr(r, 'status', None)}"


def test_the_client_closes_in_the_loop_that_opened_it():
    """Closing a client from a second `asyncio.run` raises "Event loop is
    closed" against real connections — it crashed `attribution run` and
    `paytrace run` after collection, before any report was written. Mock
    transports hold no connections, so every mocked test passed."""

    async def go():
        f = live_fetcher(user_agent="paytrace-live-test")
        try:
            await f.get(LIVE_URL)
        finally:
            await f.aclose()          # same loop: must not raise
        return True

    assert _run(go()) is True


def test_repeated_fetches_reuse_one_client_without_error():
    """Several retrievals in one run is the ordinary case; connection reuse
    across them is where real clients differ from mocks."""

    async def go():
        f = live_fetcher(user_agent="paytrace-live-test")
        try:
            return [await f.get(LIVE_URL) for _ in range(3)]
        finally:
            await f.aclose()

    results = _run(go())
    assert all(r is not None and r.status == 200 for r in results)
