"""Deep artifact extraction and the pivot loop.

The scenario: the seed domain is a clean marketing page, and the operator's
identity sits on a sibling found through a shared analytics ID. One page rarely
has the answer; the union of a portfolio's pages usually does.
"""

import asyncio

import pytest
from attribution_graph import IdKind, Reliability

from paytrace import (
    extract_artifacts,
    gravatar_hash,
    pivot_expand,
    probe_sensitive_paths,
)

# ---- extraction: quoted and unquoted HTML ---------------------------------- #

@pytest.mark.parametrize("body,kind,value", [
    ('<a href="/author/dai-nguyen/">x</a>', "wordpress_author", "dai-nguyen"),
    ("<a href=/author/dai-nguyen/>x</a>", "wordpress_author", "dai-nguyen"),
    ('<a rel="me" href="https://mastodon.social/@op">x</a>', "webfinger",
     "https://mastodon.social/@op"),
    ("<a rel=me href=https://mas.to/@op>x</a>", "webfinger", "https://mas.to/@op"),
    ("user.email = dai@snapvn.com", "git_email", "dai@snapvn.com"),
    ('<img src="https://gravatar.com/avatar/205e460b479e2e5b48aec07710c08d50">',
     "gravatar", "205e460b479e2e5b48aec07710c08d50"),
    ("login_hint=dai@snapvn.com", "oauth_login_hint", "dai@snapvn.com"),
    ('<a href="https://docs.google.com/document/d/'
     '1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/edit">d</a>', "google_doc",
     "1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"),
    ("<p>Operated by Dai Nguyen</p>", "body_name", "Dai Nguyen"),
])
def test_artifacts_are_extracted_from_both_html_styles(body, kind, value):
    ex = extract_artifacts(body, "x.example")
    assert value in ex.artifacts.get(kind, [])


def test_html_comment_leaks_are_captured():
    body = "<!-- deployed from staging.x.example.com by build bot -->"
    ex = extract_artifacts(body, "x.example")
    assert ex.artifacts.get("html_comment")
    assert "staging.x.example.com" in ex.artifacts.get("internal_host", [])


def test_service_ids_become_pivot_seeds():
    """Per-account service IDs link a portfolio like an analytics ID does."""
    body = ('https://abcdef0123456789abcdef0123456789@o1.ingest.sentry.io/1 '
            'CRISP_WEBSITE_ID="12345678-1234-1234-1234-123456789abc"')
    ex = extract_artifacts(body, "x.example")
    schemes = {i.value.split(":")[0] for i in ex.pivot_seeds}
    assert "sentry_dsn" in schemes
    assert "crisp_id" in schemes


def test_gravatar_hash_matches_a_known_email():
    """A discovered hash reverses against an address you already hold."""
    assert gravatar_hash("MyEmailAddress@example.com ") == \
        "0bc83cb571cd1c50ba6f3e8a78ef1346"


def test_response_headers_surface_origin_hosts():
    ex = extract_artifacts("<html></html>", "x.example",
                           headers={"X-Backend-Server": "origin.x.example.com",
                                    "Server": "nginx"})
    assert ex.artifacts.get("header:server") == ["nginx"]
    assert any(c.object.value == "origin.x.example.com" for c in ex.claims)


def test_yielded_identity_flag_is_accurate():
    assert extract_artifacts("<a href=/author/dai/>y</a>", "d").yielded_identity
    assert not extract_artifacts("<h1>nothing here</h1>", "d").yielded_identity


def test_generic_wordpress_authors_are_skipped():
    ex = extract_artifacts("<a href=/author/admin/>x</a>", "d")
    assert "admin" not in ex.artifacts.get("wordpress_author", [])


# ---- the pivot loop -------------------------------------------------------- #

CLEAN_SEED = ('<script src="https://www.googletagmanager.com/gtag/js?id='
              'G-SHARED123"></script><h1>Welcome</h1>')
SIBLING_A = ('<script src="https://www.googletagmanager.com/gtag/js?id='
             'G-SHARED123"></script><a href=/author/dai-nguyen/>x</a>'
             '<p>Operated by Dai Nguyen</p>')
SIBLING_B = ('<script src="https://www.googletagmanager.com/gtag/js?id='
             'G-SHARED123"></script>'
             '<img src="https://gravatar.com/avatar/'
             '205e460b479e2e5b48aec07710c08d50">')


class _Fetcher:
    def __init__(self, pages):
        self.pages = pages
        self.requests = []

    async def get(self, url, allow_html=False):
        self.requests.append(url)
        body = self.pages.get(url)

        class R:
            status = 200 if body else 404
            text = body or ""
            headers = {}
        return R()


class _Index:
    def __init__(self, siblings, holders=3):
        self._siblings, self._holders = siblings, holders

    def domains_for_analytics(self, scheme, value):
        return self._siblings if "SHARED" in value.upper() else []

    def holders_analytics(self, scheme, value):
        return self._holders


def _pages():
    return {
        "https://seed.example/": CLEAN_SEED,
        "https://sibling-a.example/": SIBLING_A,
        "https://sibling-b.example/": SIBLING_B,
    }


def test_clean_seed_recovers_identity_from_siblings():
    """The whole point: the seed names nobody, the siblings do."""
    seed_only = extract_artifacts(CLEAN_SEED, "seed.example")
    assert not seed_only.yielded_identity

    r = asyncio.run(pivot_expand(
        "seed.example", _Fetcher(_pages()),
        index=_Index(["sibling-a.example", "sibling-b.example"])))
    assert len(r.siblings) == 2
    assert "sibling-a.example" in r.identity_found_on
    assert any(c.object.value == "Dai Nguyen" for c in r.claims)


def test_pivot_claims_decay_with_distance():
    """A name three hops out is worth less than one on the seed."""
    r = asyncio.run(pivot_expand(
        "seed.example", _Fetcher(_pages()),
        index=_Index(["sibling-a.example"])))
    sibling_claims = [c for c in r.claims if c.raw.get("pivot_depth") == 1]
    assert sibling_claims
    assert all(c.weight < 1.0 for c in sibling_claims)


def test_cdn_ip_never_seeds_a_pivot():
    """A shared Cloudflare IP links to millions; it is not a sibling signal."""
    from attribution_graph import Identifier

    from paytrace.pivot import _pivotable

    ok, why = _pivotable(Identifier(IdKind.IP, "104.21.58.177"), None)
    assert not ok and "provider" in why


def test_low_selectivity_analytics_id_is_refused():
    """A GTM container on 40,000 sites is a template, not a portfolio."""
    r = asyncio.run(pivot_expand(
        "seed.example", _Fetcher(_pages()),
        index=_Index(["a.example"], holders=40_000)))
    assert r.refused
    assert any("platform artifact" in why for _, why in r.refused)
    assert not r.siblings


def test_pivot_respects_the_sibling_budget():
    pages = {"https://seed.example/": CLEAN_SEED}
    many = [f"s{i}.example" for i in range(100)]
    for m in many:
        pages[f"https://{m}/"] = CLEAN_SEED
    r = asyncio.run(pivot_expand(
        "seed.example", _Fetcher(pages), index=_Index(many), max_siblings=10))
    assert len(r.siblings) <= 10


def test_pivot_respects_max_depth():
    r = asyncio.run(pivot_expand(
        "seed.example", _Fetcher(_pages()),
        index=_Index(["sibling-a.example", "sibling-b.example"]), max_depth=1))
    assert all(s.depth <= 1 for s in r.siblings)


def test_pivot_does_not_revisit_a_domain():
    pages = _pages()
    pages["https://sibling-a.example/"] = SIBLING_A + CLEAN_SEED  # links back
    f = _Fetcher(pages)
    asyncio.run(pivot_expand(
        "seed.example", f, index=_Index(
            ["seed.example", "sibling-a.example", "sibling-b.example"])))
    fetched = [u for u in f.requests if u == "https://seed.example/"]
    assert len(fetched) == 1, "the seed must not be re-fetched"


def test_no_index_yields_no_siblings_but_still_extracts_the_seed():
    r = asyncio.run(pivot_expand("seed.example", _Fetcher(_pages())))
    assert not r.siblings
    assert r.claims  # the seed's own analytics claim


# ---- sensitive-path probing (opt-in) --------------------------------------- #

def test_probing_is_off_by_default():
    r = asyncio.run(probe_sensitive_paths(_Fetcher({}), "x.example"))
    assert not r.claims


def test_git_config_probe_yields_committer_identity():
    body = "[user]\n  name = Dai Nguyen\n  email = dai@snapvn.com\n"
    f = _Fetcher({"https://x.example/.git/config": body})
    r = asyncio.run(probe_sensitive_paths(f, "x.example", enabled=True))
    assert any(c.object.value == "dai@snapvn.com"
               and c.reliability is Reliability.AUTHORITATIVE for c in r.claims)
    assert any(c.object.kind is IdKind.PERSON_NAME for c in r.claims)


def test_env_leak_probe_yields_addresses():
    body = "SMTP_USER=ops@snapvn.com\nDB_NAME=snapvn_prod\n"
    f = _Fetcher({"https://x.example/.env": body})
    r = asyncio.run(probe_sensitive_paths(f, "x.example", enabled=True))
    assert any(c.object.value == "ops@snapvn.com" for c in r.claims)


def test_probe_is_audit_logged():
    logged = []
    f = _Fetcher({})
    asyncio.run(probe_sensitive_paths(
        f, "x.example", enabled=True, audit=lambda *a: logged.append(a)))
    assert logged, "every probe request must be audit-logged"
    assert all(a[0] == "probe" for a in logged)


def test_wp_users_api_probe_parses_json():
    import json
    body = json.dumps([{"name": "Dai Nguyen", "slug": "dai-nguyen"}])
    f = _Fetcher({"https://x.example/wp-json/wp/v2/users": body})
    r = asyncio.run(probe_sensitive_paths(f, "x.example", enabled=True))
    assert any(c.object.value == "Dai Nguyen" for c in r.claims)
