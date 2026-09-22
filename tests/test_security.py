"""Security regression tests.

Each one exists because the corresponding hole was found.
"""

import time

import pytest

from paytrace.netsec import (
    UrlPolicy,
    UrlRejected,
    check_url,
    is_safe,
    safe_host,
)

PUBLIC = lambda h: ["93.184.216.34"]           # noqa: E731
PRIVATE = lambda h: ["10.0.0.5"]               # noqa: E731
MIXED = lambda h: ["93.184.216.34", "127.0.0.1"]  # noqa: E731


# ---- SSRF: the core finding ----------------------------------------------- #
#
# `adsystem` comes straight out of the target's ads.txt, so a single published
# line turns into a request from inside the analyst's network.

@pytest.mark.parametrize("url,fragment", [
    ("https://169.254.169.254/sellers.json", "ip literal"),
    ("https://[fd00:ec2::254]/x", "ip literal"),
    ("https://localhost/ads.txt", "blocked"),
    ("https://metadata.google.internal/x", "blocked"),
    ("https://instance-data/x", "blocked"),
    ("file:///etc/passwd", "scheme"),
    ("gopher://evil/x", "scheme"),
    ("https://trusted.example@10.0.0.1/", "userinfo"),
    ("https://example.com:22/", "port"),
    ("https://example.com:6379/", "port"),
])
def test_hostile_urls_are_rejected(url, fragment):
    with pytest.raises(UrlRejected) as e:
        check_url(url, resolver=PUBLIC)
    assert fragment in str(e.value).lower()


def test_hostname_resolving_privately_is_rejected():
    """Host-string matching cannot catch this; resolution can."""
    with pytest.raises(UrlRejected, match="private"):
        check_url("https://internal.example/x", resolver=PRIVATE)


def test_dns_rebinding_is_rejected():
    """One public and one private address is a rebinding attempt, not a
    misconfiguration. ALL addresses must pass."""
    with pytest.raises(UrlRejected, match="loopback"):
        check_url("https://rebind.example/x", resolver=MIXED)


def test_unresolvable_host_is_rejected():
    with pytest.raises(UrlRejected, match="does not resolve"):
        check_url("https://nx.example/x", resolver=lambda h: [])


def test_legitimate_urls_still_pass():
    for u in ("https://pubmatic.com/sellers.json",
              "https://api.gleif.org/api/v1/lei-records",
              "http://example.co.uk/ads.txt"):
        assert is_safe(u, resolver=PUBLIC), u


def test_safe_host_filters_adstxt_derived_values():
    """The exact attack: an adsystem field pointing at cloud metadata."""
    assert safe_host("169.254.169.254") is None
    assert safe_host("localhost") is None
    assert safe_host("evil.example/../../x") is None
    assert safe_host("pubmatic.com", resolver=PUBLIC) == "pubmatic.com"


def test_allowlist_permits_self_hosted_services():
    p = UrlPolicy(allowlist=frozenset({"yente.internal"}))
    assert is_safe("https://yente.internal/search", p, resolver=PRIVATE)


def test_fetcher_validates_before_connecting():
    import asyncio

    from paytrace.net import Fetcher

    f = Fetcher(user_agent="test/1")
    r = asyncio.run(f.get("https://169.254.169.254/sellers.json"))
    assert r is None
    assert f.blocked and "IP literal" in f.blocked[0][1]
    assert f.count == 0, "no connection should have been opened"
    asyncio.run(f.aclose())


def test_fetcher_does_not_auto_follow_redirects():
    """Redirects are followed manually so each hop is re-validated. A permitted
    host redirecting to metadata defeats first-URL-only checking."""
    from paytrace.net import Fetcher

    f = Fetcher(user_agent="test/1")
    assert f._client.follow_redirects is False


# ---- ReDoS ---------------------------------------------------------------- #

def test_email_regex_does_not_backtrack_catastrophically():
    """Unbounded quantifiers around '@' took 170ms on a crafted 8KB run --
    a denial of service against an analyst scraping a page the target owns."""
    from paytrace.collectors.business import Imprint

    payload = "a" * 4000 + "@" + "b" * 4000
    t = time.perf_counter()
    Imprint.EMAIL_RE.search(payload)
    assert time.perf_counter() - t < 0.05


@pytest.mark.parametrize("email", [
    "ops@example.com", "first.last+tag@sub.example.co.uk", "a@b.io",
])
def test_bounded_email_regex_still_matches_real_addresses(email):
    from paytrace.collectors.business import Imprint
    assert Imprint.EMAIL_RE.search(email)


def test_all_hot_regexes_are_fast_on_hostile_input():
    from paytrace.agent.guards import INJECTION_PATTERNS
    from paytrace.collectors.analytics import ID_PATTERNS

    payloads = ["note for automated " * 500, "0" * 5000, "ca-pub-" + "1" * 5000]
    pats = [p for p, _ in INJECTION_PATTERNS] + [p for p, _ in ID_PATTERNS.values()]
    for pat in pats:
        for payload in payloads:
            t = time.perf_counter()
            pat.search(payload)
            assert time.perf_counter() - t < 0.05, pat.pattern


# ---- Resource limits ------------------------------------------------------ #

def test_fetcher_caps_response_size():
    """A target can serve an unbounded stream; an OOM is a DoS on the analyst."""
    from paytrace.net import Fetcher
    assert Fetcher(user_agent="t").max_bytes <= 50 * 1024 * 1024


# ---- SQL ------------------------------------------------------------------ #

def test_index_queries_are_parameterised():
    import inspect

    from paytrace import index

    src = inspect.getsource(index)
    for line in src.splitlines():
        if "execute(" in line and "%" in line:
            pytest.fail(f"string-formatted SQL: {line.strip()}")


def test_index_rejects_injection_in_lookups(tmp_path):
    from paytrace.index import AdsTxtIndex

    idx = AdsTxtIndex(str(tmp_path / "t.sqlite"))
    evil = "x'; DROP TABLE ads_record; --"
    assert idx.sites_for_seller(evil, evil) == []
    assert idx.sites_for_owner(evil) == []
    # table must survive
    assert idx.conn.execute(
        "SELECT name FROM sqlite_master WHERE name='ads_record'").fetchone()
