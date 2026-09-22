"""Network and content fingerprinting."""

import ipaddress

import pytest

from paytrace.fingerprint import (
    NEAR_DUPLICATE,
    SAME_TEMPLATE,
    cdn_for,
    compare_fingerprints,
    content_sha256,
    fingerprint_content,
    hamming,
    resolve_host,
    simhash,
    similarity,
)

TEMPLATE = """<html><head><title>{brand} Viewer</title></head><body>
<header><a href="/"><img src="/img/logo.png">Site</a><nav><a>Stories</a>
<a href="/highlights/">Highlights</a><a href="/posts/">Posts</a></nav></header>
<main><h1>{brand} Instagram Viewer</h1><p>Enter username to view with {brand}</p>
<section><h3>{brand} is Anonymous</h3><p>Nobody will know you watched.</p>
<h3>No registration</h3><p>You do not need an account.</p>
<h3>Free</h3><p>{brand} is absolutely free.</p></section>
<h2>How does {brand} work?</h2><p>{brand} is created for anonymous viewing.</p>
<h2>{brand} FAQ</h2><h3>Can I use {brand} without registering?</h3>
<blockquote>Instagram does not allow it, but our service will help.</blockquote>
</main><footer><a href="/about/">About</a><p>2026 Site</p></footer></body></html>"""

DIFFERENT = """<html><head><title>Threads Downloader</title></head><body>
<div class="wrap"><section id="hero"><h1>Download Threads videos</h1>
<ul><li>Fast</li><li>Free</li><li>No signup</li></ul></section>
<table><tr><td>Step 1</td><td>Copy the link</td></tr>
<tr><td>Step 2</td><td>Paste it here</td></tr></table>
<aside><p>Convert to MP3 quickly and easily.</p></aside></div></body></html>"""


# ---- CDN detection --------------------------------------------------------- #

@pytest.mark.parametrize("ip,provider", [
    ("104.16.0.1", "cloudflare"),
    ("172.64.0.1", "cloudflare"),
    ("2606:4700:3030::6815:3ab1", "cloudflare"),
    ("151.101.0.223", "fastly"),
])
def test_cdn_ranges_are_recognised(ip, provider):
    assert cdn_for(ip) == provider


def test_non_cdn_address_returns_none():
    assert cdn_for("198.51.100.7") is None
    assert cdn_for("not-an-ip") is None


def test_resolution_flags_a_concealed_origin():
    """Every address CDN edge means the origin is not observable, and
    co-hosting on those addresses is not evidence of anything."""
    from paytrace.fingerprint import Resolution

    r = Resolution(host="x.example",
                   addresses=["104.16.0.1", "172.64.0.1"],
                   cdn="cloudflare")
    assert r.origin_concealed
    assert "not evidence" in r.describe()


@pytest.mark.network
def test_resolution_of_a_real_host_returns_addresses():
    r = resolve_host("pypi.org")
    assert r.addresses and not r.error
    for a in r.addresses:
        ipaddress.ip_address(a)


@pytest.mark.network
def test_unresolvable_host_records_the_error():
    r = resolve_host("no-such-host.invalid")
    assert r.error and not r.addresses


# ---- hashing --------------------------------------------------------------- #

def test_content_hash_is_stable_and_distinguishing():
    a = TEMPLATE.format(brand="Mystalk")
    assert content_sha256(a) == content_sha256(a)
    assert content_sha256(a) != content_sha256(TEMPLATE.format(brand="Smihub"))


def test_hash_accepts_bytes_and_str_identically():
    assert content_sha256("abc") == content_sha256(b"abc")


# ---- SimHash: the point of the module -------------------------------------- #

def test_structural_simhash_matches_a_rebranded_template():
    """The portfolio signal: same codebase, different brand throughout.

    Exact hashing sees two different documents. Text SimHash sees different
    content. Structural SimHash sees one template, which is the truth.
    """
    a = TEMPLATE.format(brand="Mystalk")
    b = TEMPLATE.format(brand="Smihub")
    assert content_sha256(a) != content_sha256(b)
    struct = hamming(simhash(a, structural=True), simhash(b, structural=True))
    assert struct <= SAME_TEMPLATE


def test_structural_simhash_separates_unrelated_codebases():
    a = TEMPLATE.format(brand="Mystalk")
    struct = hamming(simhash(a, structural=True), simhash(DIFFERENT, structural=True))
    assert struct > SAME_TEMPLATE


def test_text_simhash_detects_near_duplicate_content():
    a = TEMPLATE.format(brand="Mystalk")
    b = a.replace("Nobody will know you watched.", "Nobody will know you watched!")
    assert hamming(simhash(a), simhash(b)) <= NEAR_DUPLICATE


def test_simhash_is_deterministic():
    a = TEMPLATE.format(brand="X")
    assert simhash(a) == simhash(a)
    assert simhash(a, structural=True) == simhash(a, structural=True)


def test_similarity_is_bounded():
    a, b = simhash("hello world foo bar"), simhash(DIFFERENT)
    assert 0.0 <= similarity(a, b) <= 1.0
    assert similarity(a, a) == 1.0


def test_empty_document_does_not_crash():
    assert isinstance(simhash(""), int)


# ---- comparison ------------------------------------------------------------ #

def test_comparison_reports_template_match_without_content_match():
    from paytrace.fingerprint import Resolution

    r = Resolution(host="x", addresses=["104.16.0.1"], cdn="cloudflare")
    a = fingerprint_content("https://a.example/", TEMPLATE.format(brand="Mystalk"),
                            resolution=r)
    b = fingerprint_content("https://a.example/smihub/", TEMPLATE.format(brand="Smihub"),
                            resolution=r)
    c = compare_fingerprints(a, b)
    assert c.same_template
    assert not c.identical_bytes
    assert "SAME TEMPLATE" in c.describe()
    assert "portfolio signal" in c.describe()


def test_shared_cdn_addresses_are_labelled_as_non_evidence():
    from paytrace.fingerprint import Resolution

    r = Resolution(host="x", addresses=["104.16.0.1"], cdn="cloudflare")
    a = fingerprint_content("https://a.example/", TEMPLATE.format(brand="A"), resolution=r)
    b = fingerprint_content("https://b.example/", DIFFERENT, resolution=r)
    c = compare_fingerprints(a, b)
    assert c.shared_cdn_only
    assert "not evidence of co-hosting" in c.describe()


def test_shared_origin_addresses_are_reported_as_evidence():
    from paytrace.fingerprint import Resolution

    r = Resolution(host="x", addresses=["198.51.100.7"])
    a = fingerprint_content("https://a.example/", TEMPLATE.format(brand="A"), resolution=r)
    b = fingerprint_content("https://b.example/", DIFFERENT, resolution=r)
    c = compare_fingerprints(a, b)
    assert not c.shared_cdn_only
    assert "shared origin addresses" in c.describe()


def test_identical_documents_are_flagged():
    body = TEMPLATE.format(brand="X")
    a = fingerprint_content("https://a.example/", body)
    b = fingerprint_content("https://b.example/", body)
    c = compare_fingerprints(a, b)
    assert c.identical_bytes and c.near_duplicate and c.same_template


def test_fingerprint_serialises_for_the_evidence_record():
    d = fingerprint_content("https://a.example/", TEMPLATE.format(brand="X")).to_dict()
    for k in ("sha256", "simhash_text", "simhash_structure", "byte_length"):
        assert k in d
    assert len(d["simhash_text"]) == 16
