"""Egress control: proxies, exit-country recording, geo-divergence.

The governing principle: content varies by the requester's apparent location, so
the exit used is part of the evidence. A capture that does not record its egress
is not reproducible even in principle.
"""

import hashlib
from datetime import datetime, timezone

import pytest

from paytrace.egress import (
    CONSENT_SENSITIVE,
    PROVIDERS,
    Egress,
    EgressPool,
    GeoDivergence,
    NetworkType,
    ProxyError,
    VantageCapture,
    redact,
    verify_egress_country,
)


def _cap(label, country, body, status=200, error=""):
    return VantageCapture(
        egress_label=label, country=country, status=status,
        body_sha256=hashlib.sha256(body.encode()).hexdigest(),
        body_bytes=len(body), fetched_at=datetime.now(timezone.utc), error=error)


# ---- configuration validation ---------------------------------------------- #

def test_unknown_provider_is_refused():
    with pytest.raises(ProxyError, match="unknown provider"):
        Egress(label="x", provider="notreal")


def test_malformed_country_is_refused():
    with pytest.raises(ProxyError, match="alpha-2"):
        Egress(label="x", country="UAE")


def test_country_is_normalised():
    assert Egress(label="x", country="AE").country == "ae"


def test_direct_egress_needs_no_credentials():
    assert Egress(label="direct").proxy_url() is None


# ---- credentials ------------------------------------------------------------ #

def test_password_must_come_from_the_environment(monkeypatch):
    """A credential in the case file is a credential in a shareable artifact."""
    monkeypatch.delenv("TEST_PW", raising=False)
    e = Egress(label="x", provider="oxylabs", username="acct",
               password_env="TEST_PW", country="ae")
    with pytest.raises(ProxyError, match="never read from the case file"):
        e.proxy_url()


def test_proxy_url_is_built_from_the_environment(monkeypatch):
    monkeypatch.setenv("TEST_PW", "s3cret")
    e = Egress(label="x", provider="oxylabs", username="acct",
               password_env="TEST_PW", country="ae")
    url = e.proxy_url()
    assert "pr.oxylabs.io:7777" in url
    assert "cc-ae" in url
    assert "s3cret" in url


def test_serialised_record_contains_no_credential(monkeypatch):
    monkeypatch.setenv("TEST_PW", "s3cret")
    e = Egress(label="x", provider="oxylabs", username="acct",
               password_env="TEST_PW", country="ae")
    e.proxy_url()
    blob = str(e.to_record())
    assert "s3cret" not in blob and "TEST_PW" not in blob


def test_redact_strips_credentials_from_text():
    assert "s3cret" not in redact("http://user:s3cret@proxy.example:7777")
    assert "<redacted>" in redact("http://user:s3cret@proxy.example:7777")


# ---- provider capabilities -------------------------------------------------- #

def test_provider_without_country_support_refuses_a_country():
    """Silently ignoring it would attribute captures to the wrong vantage point."""
    e = Egress(label="x", provider="zyte", username="u",
               password_env="P", country="ae")
    with pytest.raises(ProxyError, match="does not support"):
        e.proxy_url()


def test_generic_provider_requires_explicit_host(monkeypatch):
    monkeypatch.setenv("P", "x")
    e = Egress(label="x", provider="generic", username="u", password_env="P")
    with pytest.raises(ProxyError, match="needs an explicit host"):
        e.proxy_url()


@pytest.mark.parametrize("name", sorted(PROVIDERS))
def test_every_provider_profile_is_complete(name):
    p = PROVIDERS[name]
    assert p.username_template
    assert "{user}" in p.username_template
    if name != "generic":
        assert p.host and p.port


# ---- consent-sensitive networks --------------------------------------------- #

def test_residential_and_mobile_are_flagged():
    for net in (NetworkType.RESIDENTIAL, NetworkType.MOBILE):
        assert net in CONSENT_SENSITIVE
        e = Egress(label="x", provider="oxylabs", network=net)
        assert e.consent_sensitive
        assert "consent" in str(e.to_record()).lower()


def test_datacenter_is_not_flagged():
    e = Egress(label="x", provider="oxylabs_datacenter", network=NetworkType.DATACENTER)
    assert not e.consent_sensitive


def test_manifest_note_declares_consent_sensitive_use():
    """A run using residential exits must say so on the face of the record."""
    pool = EgressPool.from_case([
        {"label": "r", "provider": "oxylabs", "network": "residential",
         "country": "ae"}])
    note = pool.manifest_note()
    assert "residential" in note
    assert "subscribers" in note


def test_direct_only_pool_says_so_plainly():
    assert "without a proxy" in EgressPool.from_case(None).manifest_note()


# ---- pool ------------------------------------------------------------------- #

def test_pool_selects_by_label_and_country():
    pool = EgressPool.from_case([
        {"label": "direct"},
        {"label": "gulf", "country": "ae", "provider": "oxylabs"}])
    assert pool.get("gulf").country == "ae"
    assert pool.for_country("AE").label == "gulf"
    assert pool.for_country("jp") is None


def test_unknown_label_names_what_is_configured():
    pool = EgressPool.from_case([{"label": "direct"}])
    with pytest.raises(ProxyError, match="configured: direct"):
        pool.get("nope")


# ---- egress verification ---------------------------------------------------- #

def test_exit_country_mismatch_warns_about_failing_open():
    """A proxy that fails open sends traffic from the analyst's own address,
    and finding that out from the manifest afterwards is too late."""
    ok, msg = verify_egress_country("us", "ae")
    assert not ok
    assert "failed open" in msg


def test_matching_exit_country_confirms():
    ok, msg = verify_egress_country("AE", "ae")
    assert ok and "confirmed" in msg


def test_no_requested_country_always_passes():
    assert verify_egress_country("us", "")[0]


# ---- geo divergence --------------------------------------------------------- #

def test_identical_responses_do_not_diverge():
    d = GeoDivergence("https://x.example/", [
        _cap("a", "us", "<html>same</html>"),
        _cap("b", "ae", "<html>same</html>")])
    assert not d.diverges
    assert "identical from every vantage point" in d.render()


def test_different_responses_are_reported_as_a_finding():
    """Serving different corporate details by region is a decision someone made."""
    d = GeoDivergence("https://x.example/impressum", [
        _cap("eu", "de", "<html>Muster GmbH, Berlin</html>"),
        _cap("us", "us", "<html>nothing here</html>")])
    assert d.diverges
    assert d.distinct_bodies == 2
    out = d.render()
    assert "DIVERGES" in out
    assert "representing itself differently by region" in out


def test_groups_map_bodies_to_the_countries_that_received_them():
    d = GeoDivergence("https://x.example/", [
        _cap("a", "de", "A"), _cap("b", "fr", "A"), _cap("c", "us", "B")])
    groups = d.groups()
    assert len(groups) == 2
    assert sorted(next(v for v in groups.values() if len(v) == 2)) == ["de", "fr"]


def test_geo_block_is_recorded_as_a_statement_about_markets():
    d = GeoDivergence("https://x.example/", [
        _cap("a", "us", "content"),
        _cap("b", "cn", "", status=451)])
    assert "cn" in d.blocked_from
    assert "which markets the operator serves" in d.render()


def test_errors_are_not_counted_as_divergence():
    d = GeoDivergence("https://x.example/", [
        _cap("a", "us", "same"),
        _cap("b", "ae", "", status=None, error="timeout")])
    assert not d.diverges
    assert "ae" in d.blocked_from


def test_divergence_record_is_serialisable():
    d = GeoDivergence("https://x.example/", [
        _cap("a", "us", "A"), _cap("b", "ae", "B")])
    rec = d.to_record()
    assert rec["diverges"] is True
    assert rec["distinct_bodies"] == 2
    assert len(rec["captures"]) == 2
