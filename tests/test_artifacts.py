"""Deep artifact extraction and the sibling pivot.

The scenario: the seed does not name its operator, but a sibling — a domain
sharing an IP or an analytics ID — does. Every identifier extracted here is a
pivot fed back to the frontier, so an email absent from the seed surfaces two
domains over.
"""

import json

import pytest
from attribution_graph import IdKind, Reliability

from paytrace.collectors import registry
from paytrace.collectors.artifacts import (
    DeepArtifacts,
    gravatar_hash,
)


class _Fetcher:
    def __init__(self, routes=None):
        self.routes = routes or {}
        self.requests = []

    async def get(self, url, headers=None, allow_html=False):
        self.requests.append(url)
        entry = self.routes.get(url)

        class R:
            status = 200 if entry else 404
            text = (entry[0] if isinstance(entry, tuple) else entry) or ""
            headers = (entry[1] if isinstance(entry, tuple) else {}) or {}
        return R()


class _Scope:
    case_ref = "T"
    authorization = "t"

    def audit(self, *a, **k):
        pass


def _collector(routes):
    return DeepArtifacts(_Fetcher(routes), _Scope())


HTML = """<html><head>
<meta name="author" content="Tran Thi Binh">
<img src="//gravatar.com/avatar/205e460b479e2e5b48aec07710c08d50">
<script>gtag('config','G-EXAMPLE001'); fbq('init','1234567890123456');</script>
<script src="https://client-abc123.apps.googleusercontent.com/x"></script>
<!-- site built by dev@agency.example, staging at staging.realsite.example -->
<a href="https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz012345">doc</a>
</head><body>Questions? owner@realsite.example</body></html>"""


# ---- page-source extraction ------------------------------------------------ #

@pytest.mark.asyncio
async def test_extracts_the_full_artifact_set():
    c = _collector({"https://x.example/": HTML})
    claims = list(await c.collect(__import__("attribution_graph").Identifier(
        IdKind.DOMAIN, "x.example")))
    kinds = {k.value for k in
             {cl.object.kind for cl in claims if hasattr(cl.object, "kind")}}
    assert {"email", "person_name", "gravatar_hash", "analytics_id", "url"} <= kinds


@pytest.mark.asyncio
async def test_service_ids_are_marked_as_pivots():
    """Each service ID reverse-looks-up to co-owned domains — the whole point."""
    c = _collector({"https://x.example/": HTML})
    from attribution_graph import Identifier
    claims = list(await c.collect(Identifier(IdKind.DOMAIN, "x.example")))
    svc = [x for x in claims if x.object.kind is IdKind.ANALYTICS_ID]
    assert svc
    assert all("reverse-lookup" in x.raw.get("pivot", "") for x in svc)


@pytest.mark.asyncio
async def test_gravatar_hash_is_a_pivot_without_revealing_the_email():
    c = _collector({"https://x.example/": HTML})
    from attribution_graph import Identifier
    claims = list(await c.collect(Identifier(IdKind.DOMAIN, "x.example")))
    grav = [x for x in claims if x.object.kind is IdKind.GRAVATAR_HASH]
    assert grav and grav[0].reliability is Reliability.STRONG


def test_gravatar_hash_matches_the_email_that_produced_it():
    assert gravatar_hash("Owner@RealSite.Example ") == gravatar_hash(
        "owner@realsite.example")


# ---- WordPress users ------------------------------------------------------- #

@pytest.mark.asyncio
async def test_wordpress_users_are_enumerated():
    """/wp-json/wp/v2/users leaks display names and slugs by default."""
    from attribution_graph import Identifier
    users = json.dumps([{"name": "Tran Thi Binh", "slug": "tranbinh"}])
    c = _collector({"https://x.example/": "<html></html>",
                    "https://x.example/wp-json/wp/v2/users": users})
    claims = list(await c.collect(Identifier(IdKind.DOMAIN, "x.example")))
    assert any(x.object.kind is IdKind.PERSON_NAME for x in claims)
    assert any(x.object.value == "wp:tranbinh" for x in claims
               if x.object.kind is IdKind.HANDLE)


# ---- exposed files: handled, not harvested --------------------------------- #

@pytest.mark.asyncio
async def test_exposed_env_records_exposure_and_extracts_only_non_secrets():
    from attribution_graph import Identifier
    env = ("APP_NAME=RealSite\nMAIL_FROM_ADDRESS=owner@realsite.example\n"
           "DB_PASSWORD=supersecret123\nAWS_SECRET_ACCESS_KEY=AKIAsecret\n")
    c = _collector({"https://x.example/": "<html></html>",
                    "https://x.example/.env": env})
    claims = list(await c.collect(Identifier(IdKind.DOMAIN, "x.example")))

    # exposure recorded at zero weight
    exposure = [x for x in claims if "EXPOSED" in x.raw.get("artifact", "")]
    assert exposure and exposure[0].weight == 0.0

    # the email is extracted
    assert any(x.object.value == "owner@realsite.example" for x in claims
               if x.object.kind is IdKind.EMAIL)

    # secrets are never stored, anywhere in the claims
    blob = json.dumps([x.raw for x in claims] +
                      [x.object.value for x in claims if hasattr(x.object, "value")])
    assert "supersecret123" not in blob
    assert "AKIAsecret" not in blob


@pytest.mark.asyncio
async def test_exposed_git_config_yields_the_code_host_account():
    from attribution_graph import Identifier
    cfg = ('[remote "origin"]\n'
           '\turl = https://github.com/realoperator/site.git\n')
    c = _collector({"https://x.example/": "<html></html>",
                    "https://x.example/.git/config": cfg})
    claims = list(await c.collect(Identifier(IdKind.DOMAIN, "x.example")))
    handles = [x.object.value for x in claims if x.object.kind is IdKind.HANDLE]
    assert "github:realoperator" in handles


# ---- WebFinger ------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_webfinger_subject_is_extracted():
    from attribution_graph import Identifier
    wf = json.dumps({"subject": "acct:operator@realsite.example"})
    c = _collector({"https://x.example/": "<html></html>",
                    "https://x.example/.well-known/webfinger": wf})
    claims = list(await c.collect(Identifier(IdKind.DOMAIN, "x.example")))
    assert any(x.object.value == "operator@realsite.example" for x in claims
               if x.object.kind is IdKind.HANDLE)


# ---- headers --------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_response_headers_are_fingerprinted():
    from attribution_graph import Identifier
    c = _collector({"https://x.example/":
                    ("<html></html>", {"x-powered-by": "PHP/8.1", "server": "nginx"})})
    claims = list(await c.collect(Identifier(IdKind.DOMAIN, "x.example")))
    assert any("header:" in x.object.value for x in claims
               if x.object.kind is IdKind.URL)


# ---- the pivot itself ------------------------------------------------------ #

def test_pivotable_kinds_include_the_high_value_artifacts():
    """A discovered email, gravatar or handle must re-enter collection; a header
    string or raw comment must not."""
    from attribution_graph.engine import PIVOTABLE_KINDS
    assert {IdKind.EMAIL, IdKind.GRAVATAR_HASH, IdKind.ANALYTICS_ID,
            IdKind.PERSON_NAME, IdKind.HANDLE} <= PIVOTABLE_KINDS


def test_low_value_observations_are_not_pivoted():
    from attribution_graph.engine import PIVOTABLE_KINDS
    # URL-encoded headers and postal addresses are recorded, not chased.
    assert IdKind.POSTAL_ADDRESS not in PIVOTABLE_KINDS


def test_deep_artifacts_runs_early():
    """priority 1: it should run before the pivots that depend on what it finds."""
    assert registry()["deep_artifacts"].priority == 1


@pytest.mark.asyncio
async def test_staging_subdomains_become_pivots():
    """A staging host in source is a sibling: often less locked down than prod."""
    from attribution_graph import Identifier
    c = _collector({"https://x.example/": HTML})
    claims = list(await c.collect(Identifier(IdKind.DOMAIN, "x.example")))
    subs = [x.object.value for x in claims if x.object.kind is IdKind.DOMAIN]
    assert "staging.realsite.example" in subs


# ---- one identifier, one node --------------------------------------------- #

def test_collectors_agree_on_the_canonical_identifier():
    """`ca-pub-N` in page source and `pub-N` in ads.txt are one payee account.

    Two collectors captured it in different shapes — digits in one, `pub-`
    included in the other — so a single account became two graph nodes. Its
    evidence was split between them, and on a real domain the same ID came out
    STRONG_EVIDENCE under one spelling and UNSUPPORTED under the other.
    """
    from paytrace.collectors.analytics import ID_PATTERNS
    from paytrace.collectors.artifacts import _SERVICE_IDS

    digits = "5446113378742009"
    for text in (f'src="//x/adsbygoogle.js?client=ca-pub-{digits}"',
                 f"google.com, pub-{digits}, DIRECT"):
        a = ID_PATTERNS["adsense"][0].search(text)
        b = _SERVICE_IDS["adsense"].search(text)
        assert a and b and a.group(1) == b.group(1) == digits, text


def test_ua_identifiers_use_the_account_not_the_property():
    """UA-1234-1 and UA-1234-2 are two properties of one account. Keeping the
    property suffix in one collector and not the other split the account."""
    from paytrace.collectors.analytics import ID_PATTERNS
    from paytrace.collectors.artifacts import _SERVICE_IDS

    for pattern in (ID_PATTERNS["ua"][0], _SERVICE_IDS["ua"]):
        assert pattern.search("UA-12345678-3").group(1) == "UA-12345678"


def test_no_second_scheme_name_for_one_service():
    """`adsense_pub` was a separate scheme for the same accounts, which splits
    a payee by scheme name rather than by value."""
    from paytrace.collectors.analytics import ID_PATTERNS

    assert "adsense_pub" not in ID_PATTERNS
