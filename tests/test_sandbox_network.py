"""The failures that stopped this working inside a sandbox.

Every one of these is a condition an ordinary user hit and could do nothing
about: a proxy that was detected and then refused, HTTPS that could not
verify because the proxy re-signs it, a byte cap reported as a block. They are
tested together because they all present identically -- every retrieval fails
and the report reads as though the sites refused.
"""

import asyncio

import httpx
import pytest

from paytrace.netsec import UrlPolicy, UrlRejected, check_url


def _fetcher(tmp_path, **kw):
    from paytrace import Fetcher
    return Fetcher("test/1.0", cache_dir=str(tmp_path / "c"), **kw)


# ---- SSRF under a proxy ---------------------------------------------------- #

@pytest.mark.parametrize("addr,why", [
    ("127.0.0.1", "loopback"),
    ("169.254.169.254", "link-local"),
    ("10.0.0.5", "private"),
])
def test_a_private_resolution_is_refused_even_when_proxied(addr, why):
    """These checks used to be skipped outright on a proxied run.

    The reasoning was that the proxy resolves, so a local answer describes
    nothing -- true, but it discarded a check that costs nothing whenever an
    answer IS available. Most sandboxes resolve DNS perfectly well and only
    egress through the proxy, and the proxy an agent sandbox provides is
    usually on localhost, where loopback and metadata addresses are very much
    reachable.
    """
    with pytest.raises(UrlRejected) as e:
        check_url("https://host.test/x", UrlPolicy(proxied=True),
                  lambda h: [addr])
    assert why in str(e.value)


def test_an_unresolvable_host_is_allowed_when_proxied_and_recorded_as_unchecked():
    """The case the skip existed for, kept -- and no longer silent."""
    pol = UrlPolicy(proxied=True)
    assert check_url("https://nope.test/x", pol, lambda h: [])
    assert pol.rejections, "an unperformed check must leave a record"
    assert "not performed" in pol.rejections[-1][1]


def test_an_unresolvable_host_is_still_refused_without_a_proxy():
    with pytest.raises(UrlRejected):
        check_url("https://nope.test/x", UrlPolicy(), lambda h: [])


def test_a_literal_metadata_address_is_refused_through_any_route():
    for pol in (UrlPolicy(), UrlPolicy(proxied=True)):
        with pytest.raises(UrlRejected):
            check_url("https://169.254.169.254/latest/meta-data/", pol,
                      lambda h: [])


# ---- the proxy's own trust store ------------------------------------------ #

def test_an_environment_proxy_contributes_its_ca_bundle(tmp_path, monkeypatch):
    """A sandbox proxy terminates TLS and re-signs with its own CA.

    `trust_env=False` is deliberate and also meant the bundle those
    environments publish was never read, so every HTTPS retrieval failed with
    CERTIFICATE_VERIFY_FAILED while the proxy itself worked fine. Hosts looked
    like they were refusing us; they had not been asked.
    """
    from paytrace import Egress, EgressPool

    bundle = tmp_path / "ca.crt"
    bundle.write_text("-- not a real certificate --")
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))

    pool = EgressPool([Egress(label="environment", provider="environment")],
                      "environment")
    f = _fetcher(tmp_path, egress=pool)
    assert f._trust_store(pool.get()) == str(bundle)
    assert f.tls_intercepted == "SSL_CERT_FILE"


@pytest.mark.parametrize("provider,label", [("direct", "direct"),
                                            ("oxylabs", "paid")])
def test_only_an_environment_proxy_gets_that_trust(provider, label,
                                                   tmp_path, monkeypatch):
    """Deliberately narrow: an environment variable must not be able to add
    trust to a declared commercial egress or to a direct connection. That
    would let whoever set the variable choose who we believe."""
    from paytrace import Egress, EgressPool

    bundle = tmp_path / "ca.crt"
    bundle.write_text("x")
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))

    e = Egress(label=label, provider=provider,
               **({"host": "gw.test", "port": 1080, "username": "u",
                   "password_env": "TEST_PROXY_PW"} if provider != "direct"
                  else {}))
    pool = EgressPool([e], label)
    f = _fetcher(tmp_path, egress=pool)
    assert f._trust_store(e) == ""
    assert f.tls_intercepted == ""


def test_a_ca_path_that_does_not_exist_is_ignored(tmp_path, monkeypatch):
    """And nothing else is standing in for it.

    The first version of this test passed a missing path in SSL_CERT_FILE and
    asserted no bundle was adopted -- on a machine where REQUESTS_CA_BUNDLE
    also pointed at a real file, so the fall-through to the next variable (the
    correct behaviour) looked like a failure. All three have to be cleared for
    the assertion to mean what it says.
    """
    from paytrace import Egress, EgressPool

    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "absent.crt"))
    pool = EgressPool([Egress(label="environment", provider="environment")],
                      "environment")
    f = _fetcher(tmp_path, egress=pool)
    assert f._trust_store(pool.get()) == ""


# ---- a byte cap is not a block -------------------------------------------- #

def test_a_capped_body_is_a_partial_read_not_a_blocked_one(tmp_path):
    """It completed and returned usable content, and an evidence record was
    written for it with outcome="truncated". Filing it under `blocked` claimed
    the fetch produced no evidence and forced the run INCOMPLETE -- which an
    ordinary large file triggers."""
    cap = 2048

    def handler(request):
        return httpx.Response(200, content=b"x" * (cap * 4),
                              headers={"content-type": "text/plain"})

    f = _fetcher(tmp_path, max_bytes=cap, resolver=lambda h: ["93.184.216.34"])
    f._clients["direct"] = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False)
    r = asyncio.run(f.get("https://example.test/big"))
    asyncio.run(f.aclose())

    assert r is not None and len(r.text) <= cap
    assert [p for p in f.truncated_reads if "truncated" in p[1]]
    assert not [b for b in f.blocked if "truncated" in b[1]]
