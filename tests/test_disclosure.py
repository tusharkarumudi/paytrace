"""Mandated-disclosure collectors.

The gap these close: an anonymous site publishes a contact email anyone can read
off the page. The same operator, to ship an extension or claim DMCA safe
harbour, must file a real name with a body that publishes it.
"""

import json

import pytest
from attribution_graph import IdKind, Predicate, Reliability

from paytrace.collectors.disclosure import (
    AppStoreDeveloper,
    DmcaAgent,
    ExtensionStoreDeveloper,
    extract_store_identifiers,
)


class _Fetcher:
    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    async def get(self, url, headers=None, allow_html=False):
        self.requests.append(url)
        body = self.routes.get(url)

        class R:
            status = 200 if body else 404
            text = body or ""
        return R()

    async def get_json(self, url, headers=None):
        r = await self.get(url)
        return json.loads(r.text) if r.text else None


class _Scope:
    case_ref = "T"
    authorization = "t"

    def audit(self, *a, **k):
        pass


# ---- the pivot that was missing -------------------------------------------- #

def test_store_links_are_extracted_from_markup():
    """Extension IDs were being pulled out as opaque URLs and never followed."""
    html = """
    <a href="https://chromewebstore.google.com/detail/foo/hbpilcehcbemgmpfmdgfbhhmgobbncnp">c</a>
    <a href="https://microsoftedge.microsoft.com/addons/detail/bar/fcmdknjldlmniklpdgjpbbmkojbdkbcp">e</a>
    <a href="https://addons.mozilla.org/en-US/firefox/addon/threads-voice-downloader/">f</a>
    <a href="https://play.google.com/store/apps/details?id=com.example.app">p</a>
    <a href="https://apps.apple.com/us/app/foo/id1234567890">a</a>
    """
    ids = extract_store_identifiers(html)
    assert "ext:chrome/hbpilcehcbemgmpfmdgfbhhmgobbncnp" in ids
    assert "ext:edge/fcmdknjldlmniklpdgjpbbmkojbdkbcp" in ids
    assert "ext:firefox/threads-voice-downloader" in ids
    assert "app:play/com.example.app" in ids
    assert "app:appstore/1234567890" in ids


def test_no_store_links_yields_nothing():
    assert extract_store_identifiers("<p>no links here</p>") == []


def test_analytics_collector_now_emits_store_pivots():
    """Closes the loop: URL was emitted and no collector accepted it."""
    import inspect

    from paytrace.collectors import analytics
    assert "extract_store_identifiers" in inspect.getsource(analytics)


def test_url_kind_is_now_an_accepted_input():
    from paytrace.collectors import registry

    accepting = [n for n, c in registry().items() if IdKind.URL in getattr(c, "accepts", ())]
    assert accepting, "IdKind.URL must be pivotable, not just emitted"


# ---- extension stores ------------------------------------------------------ #

@pytest.mark.asyncio
async def test_chrome_listing_yields_publisher_and_trader():
    from attribution_graph import Identifier

    url = "https://chromewebstore.google.com/detail/hbpilcehcbemgmpfmdgfbhhmgobbncnp"
    page = """<div>Offered by: Example Media Holdings Ltd</div>
    <div>Trader: Example Media Holdings Ltd</div>
    <div>Address: 12 Example Street, Hanoi, Vietnam</div>
    <div>support@examplemedia.test</div>"""
    c = ExtensionStoreDeveloper(_Fetcher({url: page}), _Scope())
    claims = list(await c.collect(
        Identifier(IdKind.URL, "ext:chrome/hbpilcehcbemgmpfmdgfbhhmgobbncnp")))

    names = [x for x in claims if x.predicate is Predicate.LEGAL_NAME]
    assert names and names[0].reliability is Reliability.AUTHORITATIVE
    assert any(x.predicate is Predicate.REGISTERED_ADDRESS for x in claims)
    assert any(x.object.kind is IdKind.EMAIL for x in claims)


@pytest.mark.asyncio
async def test_individual_publisher_is_typed_as_a_person():
    from attribution_graph import Identifier

    url = "https://chromewebstore.google.com/detail/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    c = ExtensionStoreDeveloper(
        _Fetcher({url: "<div>Offered by: HOANG PHU LINH</div>"}), _Scope())
    claims = list(await c.collect(
        Identifier(IdKind.URL, "ext:chrome/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")))
    assert any(x.object.kind is IdKind.PERSON_NAME for x in claims)


@pytest.mark.asyncio
async def test_firefox_amo_json_is_parsed_properly():
    from attribution_graph import Identifier

    url = "https://addons.mozilla.org/api/v5/addons/addon/threads-voice-downloader/"
    body = json.dumps({"authors": [
        {"id": 1, "name": "Dai Nguyen", "homepage": "https://snapvn.com/"}]})
    c = ExtensionStoreDeveloper(_Fetcher({url: body}), _Scope())
    claims = list(await c.collect(
        Identifier(IdKind.URL, "ext:firefox/threads-voice-downloader")))
    assert any(x.object.kind is IdKind.PERSON_NAME and x.object.value == "Dai Nguyen"
               for x in claims)
    assert any(x.object.kind is IdKind.DOMAIN for x in claims)


@pytest.mark.asyncio
async def test_platform_emails_are_not_treated_as_operator_contacts():
    from attribution_graph import Identifier

    url = "https://chromewebstore.google.com/detail/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    c = ExtensionStoreDeveloper(
        _Fetcher({url: "<div>Offered by: X Ltd</div><div>abuse@google.com</div>"}),
        _Scope())
    claims = list(await c.collect(
        Identifier(IdKind.URL, "ext:chrome/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")))
    assert not [x for x in claims if x.object.kind is IdKind.EMAIL]


@pytest.mark.asyncio
async def test_malformed_identifier_is_ignored():
    from attribution_graph import Identifier

    c = ExtensionStoreDeveloper(_Fetcher({}), _Scope())
    assert list(await c.collect(Identifier(IdKind.URL, "https://example.com/"))) == []


# ---- app stores ------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_play_listing_yields_dsa_trader_details():
    from attribution_graph import Identifier

    url = "https://play.google.com/store/apps/details?id=com.example.app&hl=en&gl=DE"
    page = """<div>Trader: Example Media Holdings Ltd</div>
    <div>Address: 12 Example Street, Hanoi</div><div>dev@examplemedia.test</div>"""
    c = AppStoreDeveloper(_Fetcher({url: page}), _Scope())
    claims = list(await c.collect(Identifier(IdKind.URL, "app:play/com.example.app")))
    legal = [x for x in claims if x.predicate is Predicate.LEGAL_NAME]
    assert legal and legal[0].reliability is Reliability.AUTHORITATIVE
    assert "DSA trader verification" in legal[0].raw["basis"]


# ---- DMCA ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_dmca_agent_yields_organisation_and_named_agent():
    """The highest-yield name source for a content-serving site, and the least
    used: safe harbour requires filing a real name and address."""
    from attribution_graph import Identifier

    url = "https://dmca.copyright.gov/osp/api/service-providers?search=instavisor.net"
    body = json.dumps({"results": [{
        "id": "42", "serviceProviderName": "Example Media Holdings Ltd",
        "agentName": "Jane Q Operator",
        "address": "12 Example Street, Hanoi, Vietnam",
        "email": "dmca@examplemedia.test"}]})
    c = DmcaAgent(_Fetcher({url: body}), _Scope())
    claims = list(await c.collect(Identifier(IdKind.DOMAIN, "instavisor.net")))

    assert any(x.predicate is Predicate.LEGAL_NAME for x in claims)
    officer = [x for x in claims if x.predicate is Predicate.OFFICER_OF]
    assert officer and officer[0].subject.kind is IdKind.PERSON_NAME
    assert officer[0].raw["role"] == "DMCA designated agent"
    assert all(x.reliability is Reliability.AUTHORITATIVE for x in claims)


@pytest.mark.asyncio
async def test_dmca_absent_registration_returns_nothing():
    from attribution_graph import Identifier

    url = "https://dmca.copyright.gov/osp/api/service-providers?search=x.example"
    c = DmcaAgent(_Fetcher({url: json.dumps({"results": []})}), _Scope())
    assert list(await c.collect(Identifier(IdKind.DOMAIN, "x.example"))) == []


# ---- simhash interoperability ---------------------------------------------- #

def test_wellknown_simhash_width_is_recorded_as_incompatible():
    """well-known.dev publishes 48-bit values (12 hex chars). Ours are 64-bit.
    A Hamming distance across the two is meaningless."""
    from paytrace.fingerprint import SIMHASH_BITS, WELLKNOWN_SIMHASH_BITS

    assert WELLKNOWN_SIMHASH_BITS == 48
    assert SIMHASH_BITS != WELLKNOWN_SIMHASH_BITS
    assert len("d5d3d1c05307") * 4 == WELLKNOWN_SIMHASH_BITS
