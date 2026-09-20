"""Transport guarantees the docstrings previously claimed but did not provide.

Three defects an external audit found, each a case where a comment described a
protection the code did not implement:

  1. `max_bytes` sliced `r.content`, which materialises the whole body first
  2. `EgressPool` was held beside the client, not used by it
  3. the cache key omitted the egress, so a US capture served a DE request
"""

import asyncio

import httpx
import pytest

from paytrace.egress import EgressPool, NetworkType, ProxyError
from paytrace.net import Fetcher

#: A resolver that returns a public address without touching DNS. Mocking the
#: HTTP transport was not enough: URL validation performed real DNS first and
#: returned None before the mock was ever reached, so the tests were not
#: deterministic and failed in any sandbox without outbound DNS.
PUBLIC_RESOLVER = lambda host: ["93.184.216.34"]  # noqa: E731


def _fetcher(tmp_path, **kw):
    kw.setdefault("resolver", PUBLIC_RESOLVER)
    return Fetcher(user_agent="test/1", cache_dir=tmp_path / "cache", **kw)


# ---- streaming size cap ----------------------------------------------------- #

def test_body_is_capped_without_materialising_the_whole_response(tmp_path):
    """A hostile endpoint can stream gigabytes. The read must stop at the cap,
    not slice after the fact."""
    cap = 4096
    served = 0

    def handler(request):
        nonlocal served
        served = 5 * 1024 * 1024
        return httpx.Response(200, content=b"A" * served)

    f = _fetcher(tmp_path, max_bytes=cap)
    f._clients["direct"] = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False)

    r = asyncio.run(f.get("https://example.com/big",
                          headers=None))
    assert r is not None
    assert len(r.text) <= cap
    assert any("truncated" in reason for _, reason in f.blocked)
    asyncio.run(f.aclose())


def test_small_bodies_are_not_truncated(tmp_path):
    def handler(request):
        return httpx.Response(200, content=b"<html>small</html>")

    f = _fetcher(tmp_path, max_bytes=1024)
    f._clients["direct"] = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False)
    r = asyncio.run(f.get("https://example.com/"))
    assert r.text == "<html>small</html>"
    assert not f.blocked
    asyncio.run(f.aclose())


def test_read_capped_stops_at_the_limit():
    """Unit-level: the reader must not accumulate beyond max_bytes."""
    class Resp:
        async def aiter_bytes(self):
            for _ in range(100):
                yield b"X" * 1000

    f = Fetcher(user_agent="t", max_bytes=2500)
    body, truncated = asyncio.run(f._read_capped(Resp()))
    assert len(body) == 2500
    assert truncated


# ---- egress actually controls transport ------------------------------------- #

def test_each_egress_gets_its_own_client(tmp_path, monkeypatch):
    """The pool used to be metadata beside a single client, so the manifest
    recorded a vantage point the transport never used."""
    monkeypatch.setenv("PW", "secret")
    pool = EgressPool.from_case([
        {"label": "direct"},
        {"label": "gulf", "provider": "oxylabs_datacenter", "network": "datacenter",
         "country": "ae", "username": "acct", "password_env": "PW"}])
    f = _fetcher(tmp_path, egress=pool)

    a = f.client_for("direct")
    b = f.client_for("gulf")
    assert a is not b
    assert f.client_for("direct") is a, "clients are cached per label"
    asyncio.run(f.aclose())


def test_direct_egress_has_no_proxy(tmp_path):
    f = _fetcher(tmp_path)
    assert f.egress.get().proxy_url() is None
    assert f.client_for() is not None
    asyncio.run(f.aclose())


def test_misconfigured_egress_raises_rather_than_falling_back(tmp_path, monkeypatch):
    """Silently falling back to direct would attribute captures to a vantage
    point that was never used."""
    monkeypatch.delenv("MISSING_PW", raising=False)
    pool = EgressPool.from_case([
        {"label": "x", "provider": "oxylabs", "country": "ae",
         "username": "u", "password_env": "MISSING_PW"}])
    f = _fetcher(tmp_path, egress=pool)
    with pytest.raises(ProxyError):
        f.client_for("x")
    asyncio.run(f.aclose())


def test_aclose_closes_every_egress_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PW", "s")
    pool = EgressPool.from_case([
        {"label": "direct"},
        {"label": "gulf", "provider": "oxylabs", "country": "ae",
         "username": "u", "password_env": "PW"}])
    f = _fetcher(tmp_path, egress=pool)
    f.client_for("direct")
    f.client_for("gulf")
    assert len(f._clients) == 2
    asyncio.run(f.aclose())
    assert not f._clients


# ---- cache key includes the egress ------------------------------------------ #

def test_same_url_from_different_egresses_does_not_collide(tmp_path, monkeypatch):
    """Content varies by vantage point. A shared key made a US capture answer a
    request that asked for a DE vantage point."""
    monkeypatch.setenv("PW", "s")
    pool = EgressPool.from_case([
        {"label": "us", "provider": "oxylabs", "country": "us",
         "username": "u", "password_env": "PW"},
        {"label": "de", "provider": "oxylabs", "country": "de",
         "username": "u", "password_env": "PW"}])
    f = _fetcher(tmp_path, egress=pool)
    a = f._cache_path("https://x.example/", None, "us")
    b = f._cache_path("https://x.example/", None, "de")
    assert a != b
    asyncio.run(f.aclose())


def test_same_url_same_egress_hits_the_same_cache_entry(tmp_path):
    f = _fetcher(tmp_path)
    assert (f._cache_path("https://x.example/", None, "direct")
            == f._cache_path("https://x.example/", None, "direct"))
    asyncio.run(f.aclose())


# ---- SSRF still applies through a proxy ------------------------------------- #

def test_ssrf_guard_runs_before_any_client_is_selected(tmp_path):
    """A proxy does not exempt a URL from validation."""
    f = _fetcher(tmp_path)
    r = asyncio.run(f.get("https://169.254.169.254/latest/meta-data/"))
    assert r is None
    assert f.blocked and "ip literal" in f.blocked[0][1].lower()
    assert f.count == 0, "no connection should have been opened"
    asyncio.run(f.aclose())


def test_consent_sensitive_egress_is_visible_on_the_fetcher(tmp_path):
    pool = EgressPool.from_case([
        {"label": "r", "provider": "oxylabs", "network": "residential",
         "country": "de"}])
    f = _fetcher(tmp_path, egress=pool)
    assert f.egress.consent_sensitive
    assert "subscribers" in f.egress.manifest_note()
    asyncio.run(f.aclose())


def test_egress_defaults_to_direct_when_unconfigured(tmp_path):
    f = _fetcher(tmp_path)
    assert f.egress.get().is_direct
    assert f.egress.get().network is NetworkType.DIRECT
    asyncio.run(f.aclose())


def test_egress_record_carries_no_credential(tmp_path, monkeypatch):
    monkeypatch.setenv("PW", "s3cret")
    pool = EgressPool.from_case([
        {"label": "x", "provider": "oxylabs", "country": "ae",
         "username": "u", "password_env": "PW"}])
    f = _fetcher(tmp_path, egress=pool)
    f.client_for("x")
    assert "s3cret" not in str(pool.to_record())
    asyncio.run(f.aclose())


def test_egress_object_is_the_transport_dependency():
    """Structural: Fetcher must build clients from the pool, not hold it beside
    an unrelated client."""
    import inspect
    src = inspect.getsource(Fetcher)
    assert "def client_for" in src
    assert "egress.proxy_url()" in src
    assert "proxy" in src


# ---- EA-09: budget binds every physical request ---------------------------- #

def test_budget_is_enforced_on_redirect_hops(tmp_path):
    """Checked once at entry, a redirect chain ran past the limit: with
    max_requests=1 a 302 -> 200 sequence completed with count=2."""
    from paytrace.net import BudgetExceeded

    def handler(request):
        if request.url.path == "/a":
            return httpx.Response(302, headers={"location": "https://example.com/b"})
        return httpx.Response(200, content=b"ok")

    f = _fetcher(tmp_path, max_requests=1)
    f._clients["direct"] = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False)
    with pytest.raises(BudgetExceeded):
        asyncio.run(f.get("https://example.com/a"))
    assert f.count <= 1
    asyncio.run(f.aclose())


# ---- EA-03: capture recording is a transport invariant --------------------- #

def test_every_fetch_records_a_capture(tmp_path):
    """The runner built an EvidenceLog, never passed it anywhere, then wrote
    and self-verified it -- so a run that made real requests produced an empty
    package with evidence_verified=True."""
    class Log:
        def __init__(self):
            self.captures = []

        def record(self, url, status, body, **kw):
            self.captures.append((url, status, len(body), kw.get("outcome")))

    log = Log()
    f = _fetcher(tmp_path, evidence_log=log)
    f._clients["direct"] = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"hi")),
        follow_redirects=False)
    asyncio.run(f.get("https://example.com/"))
    assert log.captures
    assert log.captures[0][0] == "https://example.com/"
    asyncio.run(f.aclose())



# ---- EA-06: policy is consulted, not merely constructed -------------------- #


# ---- EA-18: resolver injection --------------------------------------------- #

def test_resolver_is_injectable_for_deterministic_tests(tmp_path):
    f = _fetcher(tmp_path, resolver=lambda h: ["10.0.0.5"])
    assert asyncio.run(f.get("https://internal.example/")) is None
    assert any("private" in reason for _, reason in f.blocked)
    asyncio.run(f.aclose())


# ---- RB-01: the REAL PolicyEngine against the REAL Fetcher ----------------- #
#
# These previously used a hand-written policy double implementing `allowed` and
# `reason`. The real PolicyEngine.evaluate is `async (fetcher, url)` and its
# FetchDecision exposes `note` and `should_fetch` -- so the doubles passed while
# the production seam raised TypeError inside every collector, which the engine
# swallowed as ordinary collector unavailability. A run finished with 0 claims,
# 0 captures and evidence_verified=True.
#
# Doubles that do not match the real interface are worse than no test.

ROBOTS = b"User-agent: *\nDisallow: /private\n"


def _policy_handler(request):
    if request.url.path == "/robots.txt":
        return httpx.Response(200, content=ROBOTS)
    return httpx.Response(200, content=b"page body")


def _with_policy(tmp_path, mode, evidence_log=None):
    from attribution_graph import PolicyEngine, RobotsPolicy

    f = _fetcher(tmp_path / mode, evidence_log=evidence_log,
                 policy=PolicyEngine(policy=RobotsPolicy(mode), user_agent="test/1"))
    f._clients["direct"] = httpx.AsyncClient(
        transport=httpx.MockTransport(_policy_handler), follow_redirects=False)
    return f


def test_respect_does_not_fetch_a_disallowed_path(tmp_path):
    f = _with_policy(tmp_path, "respect")
    assert asyncio.run(f.get("https://example.com/private")) is None
    assert f.policy_decisions
    assert any("fetch policy" in reason for _, reason in f.blocked)
    asyncio.run(f.aclose())


def test_record_fetches_a_disallowed_path_and_records_the_directive(tmp_path):
    """`allowed` is what robots says; `should_fetch` is what the policy decides.
    Only the latter may veto -- under `record`, a disallowed path is fetched
    *and* recorded as disallowed, which is the entire point of that mode."""
    f = _with_policy(tmp_path, "record")
    r = asyncio.run(f.get("https://example.com/private"))
    assert r is not None and r.status == 200
    assert f.policy_decisions
    d = f.policy_decisions[0]
    assert d.should_fetch and not d.allowed
    asyncio.run(f.aclose())


def test_ignore_does_not_consult_robots(tmp_path):
    f = _with_policy(tmp_path, "ignore")
    assert asyncio.run(f.get("https://example.com/private")) is not None
    assert "not checked" in f.policy_decisions[0].robots_directive
    asyncio.run(f.aclose())


def test_allowed_path_is_fetched_under_respect(tmp_path):
    f = _with_policy(tmp_path, "respect")
    assert asyncio.run(f.get("https://example.com/public")) is not None
    asyncio.run(f.aclose())


def test_robots_lookup_does_not_recurse_through_policy(tmp_path):
    """PolicyEngine fetches robots.txt through this same Fetcher. Evaluating
    policy for that request would re-enter the engine."""
    f = _with_policy(tmp_path, "respect")
    asyncio.run(f.get("https://example.com/private"))
    robots_decisions = [d for d in f.policy_decisions if "robots.txt" in d.url]
    assert not robots_decisions, "the robots fetch must bypass policy evaluation"
    assert not f._in_policy_lookup, "the guard must be reset"
    asyncio.run(f.aclose())


def test_policy_refusal_is_captured_as_evidence(tmp_path):
    """A package containing only successes cannot show what was tried and
    refused."""
    class Log:
        def __init__(self):
            self.captures = []

        def record(self, url, status, body, **kw):
            self.captures.append(kw.get("outcome"))

    log = Log()
    f = _with_policy(tmp_path, "respect", evidence_log=log)
    asyncio.run(f.get("https://example.com/private"))
    assert "refused" in log.captures
    asyncio.run(f.aclose())


# ---- RA-01: every physical response is captured ---------------------------- #

def test_error_responses_are_captured(tmp_path):
    """Returning on status >= 400 before recording meant a package could show
    one request and zero captures. "Checked and got nothing" is precisely what
    distinguishes a negative result from an unchecked one."""
    class Log:
        def __init__(self):
            self.captures = []

        def record(self, url, status, body, **kw):
            self.captures.append((status, kw.get("outcome")))

    log = Log()
    f = _fetcher(tmp_path, evidence_log=log)
    f._clients["direct"] = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(404)),
        follow_redirects=False)
    asyncio.run(f.get("https://example.com/missing"))
    assert log.captures == [(404, "error")]
    asyncio.run(f.aclose())


def test_redirect_hops_are_captured(tmp_path):
    """Only the final response was recorded; the chain is part of what
    happened."""
    class Log:
        def __init__(self):
            self.captures = []

        def record(self, url, status, body, **kw):
            self.captures.append(kw.get("outcome"))

    def handler(request):
        if request.url.path == "/a":
            return httpx.Response(302, headers={"location": "https://example.com/b"})
        return httpx.Response(200, content=b"ok")

    log = Log()
    f = _fetcher(tmp_path, evidence_log=log)
    f._clients["direct"] = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False)
    asyncio.run(f.get("https://example.com/a"))
    assert log.captures == ["redirect", "success"]
    assert f.count == 2
    asyncio.run(f.aclose())


def test_provenance_mismatch_raises_rather_than_dropping_egress(tmp_path):
    """The TypeError fallback quietly became the normal path once `egress` was
    added: every capture recorded collector="fetcher" and egress="". A
    signature mismatch here is a defect, not a compatibility case."""
    class OldLog:
        captures: list = []

        def record(self, url, status, body, collector=""):
            raise TypeError("unexpected keyword argument 'egress'")

    f = _fetcher(tmp_path, evidence_log=OldLog())
    f._clients["direct"] = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x")),
        follow_redirects=False)
    with pytest.raises(RuntimeError, match="version mismatch"):
        asyncio.run(f.get("https://example.com/"))
    asyncio.run(f.aclose())


# ---- V1-V4: evidence provenance and credential handling -------------------- #

def test_redirect_evidence_names_the_url_that_served_the_body(tmp_path):
    """The final 200 of a redirect chain was recorded under the STARTING url,
    so the manifest said a body came from somewhere it did not."""
    from attribution_graph import CaseScope, EvidenceLog

    (tmp_path / "c.yaml").write_text(
        f"case_ref: T\nauthorization: t\nseeds: [domain:a.example]\n"
        f"audit_path: {tmp_path / 'a.jsonl'}\n")
    log = EvidenceLog(CaseScope.load(str(tmp_path / "c.yaml")), tmp_path / "ev")

    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "https://x.example/final"})
        return httpx.Response(200, content=b"final body")

    f = _fetcher(tmp_path, evidence_log=log)
    f._clients["direct"] = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False)
    asyncio.run(f.get("https://x.example/start"))
    asyncio.run(f.aclose())

    assert [c.url for c in log.captures] == [
        "https://x.example/start", "https://x.example/final"]
    assert log.captures[-1].status == 200


def test_cache_hit_preserves_the_exact_wire_bytes(tmp_path):
    """The cache stored decoded text and re-encoded it on read, so a cache-hit
    capture recorded the digest of a byte sequence the origin never sent. The
    package was making a precise claim about bytes that did not exist."""
    import hashlib

    from attribution_graph import CaseScope, EvidenceLog

    body = b"bytes with \xc3\xa9 and \xef\xbb\xbf"
    digest = hashlib.sha256(body).hexdigest()

    def newlog(name):
        p = tmp_path / name
        p.mkdir()
        (p / "c.yaml").write_text(
            f"case_ref: T\nauthorization: t\nseeds: [domain:a.example]\n"
            f"audit_path: {p / 'a.jsonl'}\n")
        return EvidenceLog(CaseScope.load(str(p / "c.yaml")), p / "ev")

    log1 = newlog("run1")
    f = _fetcher(tmp_path, evidence_log=log1)
    f._clients["direct"] = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=body)),
        follow_redirects=False)
    asyncio.run(f.get("https://x.example/"))
    asyncio.run(f.aclose())
    assert log1.captures[0].body_sha256 == digest

    log2 = newlog("run2")
    f2 = _fetcher(tmp_path, evidence_log=log2)
    r = asyncio.run(f2.get("https://x.example/"))
    asyncio.run(f2.aclose())
    assert r.from_cache
    assert log2.captures[0].body_sha256 == digest, \
        "a cache hit must record the wire digest, not a re-encoding"
    assert log2.captures[0].outcome == "cache"


def test_cache_hit_keeps_the_original_retrieval_time(tmp_path):
    """A cache hit that claims this run's timestamp misdates the evidence."""
    from attribution_graph import CaseScope, EvidenceLog

    (tmp_path / "c.yaml").write_text(
        f"case_ref: T\nauthorization: t\nseeds: [domain:a.example]\n"
        f"audit_path: {tmp_path / 'a.jsonl'}\n")
    log1 = EvidenceLog(CaseScope.load(str(tmp_path / "c.yaml")), tmp_path / "ev1")
    f = _fetcher(tmp_path, evidence_log=log1)
    f._clients["direct"] = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x")),
        follow_redirects=False)
    asyncio.run(f.get("https://x.example/"))
    asyncio.run(f.aclose())

    log2 = EvidenceLog(CaseScope.load(str(tmp_path / "c.yaml")), tmp_path / "ev2")
    f2 = _fetcher(tmp_path, evidence_log=log2)
    asyncio.run(f2.get("https://x.example/"))
    asyncio.run(f2.aclose())
    assert "originally retrieved" in log2.captures[0].note


def test_no_api_token_rides_in_a_request_url():
    """Tokens in query strings persist into evidence captures, cache keys,
    audit entries and exception text. Evidence packages are built to be shared."""
    import re
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "src" / "paytrace"
           / "collectors" / "registries.py").read_text()
    assert not re.search(r'url = f"[^"]*(api_token|api_key|token)=', src)
    assert "def _auth(" in src
