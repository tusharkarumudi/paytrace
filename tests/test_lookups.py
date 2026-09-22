"""Third-party lookup services and specialist registries.

The scoring rule these encode: a service that asserts a result without exposing
its method is a different epistemic object from a corpus you built and can
audit. Presence is informative; absence is not.
"""


import pytest
from attribution_graph import Identifier, IdKind, Reliability, SourceClass

from paytrace.collectors import registry
from paytrace.collectors.lookups import NOT_AUTOMATED


class _Fetcher:
    def __init__(self, routes=None, js=None):
        self.routes, self.js = routes or {}, js or {}
        self.requests = []

    async def get(self, url, headers=None, allow_html=False):
        self.requests.append(url)
        body = self.routes.get(url)

        class R:
            status = 200 if body else 404
            text = body or ""
        return R()

    async def get_json(self, url, headers=None):
        self.requests.append(url)
        return self.js.get(url)


class _Scope:
    case_ref = "T"
    authorization = "t"

    def audit(self, *a, **k):
        pass


def _mk(name, fetcher):
    return registry()[name](fetcher, _Scope())


# ---- reverse publisher ID: the core mechanic without a corpus -------------- #

@pytest.mark.asyncio
async def test_reverse_lookup_recovers_domains_from_a_publisher_id():
    url = "https://dnslytics.com/reverse-adsense/1234567890123456"
    page = "<a>sitea.example</a><a>siteb.example</a><a>dnslytics.com</a>"
    c = _mk("reverse_publisher_id", _Fetcher({url: page}))
    claims = list(await c.collect(
        Identifier(IdKind.ANALYTICS_ID, "adsense:1234567890123456")))
    domains = {x.object.value for x in claims if x.object.kind is IdKind.DOMAIN}
    assert {"sitea.example", "siteb.example"} <= domains
    assert "dnslytics.com" not in domains, "service chrome must be filtered"


@pytest.mark.asyncio
async def test_reverse_lookup_is_one_observation_per_service():
    """One query against one index is one observation, however many results."""
    url = "https://dnslytics.com/reverse-adsense/111"
    page = "".join(f"<a>s{i}.example</a>" for i in range(40))
    c = _mk("reverse_publisher_id", _Fetcher({url: page}))
    claims = list(await c.collect(Identifier(IdKind.ANALYTICS_ID, "adsense:111")))
    assert len(claims) > 10
    assert len({x.correlation_group for x in claims}) == 1


@pytest.mark.asyncio
async def test_third_party_lookup_scores_below_a_corpus_lookup():
    """A service that will not publish its coverage cannot be authoritative."""
    url = "https://dnslytics.com/reverse-adsense/222"
    c = _mk("reverse_publisher_id", _Fetcher({url: "<a>x.example</a>"}))
    claims = list(await c.collect(Identifier(IdKind.ANALYTICS_ID, "adsense:222")))
    assert all(x.reliability is Reliability.MODERATE for x in claims)
    assert Reliability.MODERATE < Reliability.AUTHORITATIVE


@pytest.mark.asyncio
async def test_no_results_records_absence_as_uninformative():
    c = _mk("reverse_publisher_id", _Fetcher({}))
    claims = list(await c.collect(Identifier(IdKind.ANALYTICS_ID, "adsense:999")))
    assert claims and claims[0].weight == 0.0
    assert "does not mean no other domains" in claims[0].raw.get("note", "")


# ---- ICIJ Offshore Leaks --------------------------------------------------- #

@pytest.mark.asyncio
async def test_offshore_leaks_returns_entities_with_the_required_qualifier():
    """Appearing in the database is not evidence of wrongdoing, and a report
    that implies otherwise is defamatory."""
    url = "https://offshoreleaks.icij.org/api/v1/search?q=Example%20Media%20Ltd"
    body = [{"node_id": "1", "name": "Example Media Ltd",
             "jurisdiction": "BVI", "sourceID": "Panama Papers",
             "address": "PO Box 1, Road Town"}]
    c = _mk("icij_offshore_leaks", _Fetcher(js={url: body}))
    claims = list(await c.collect(
        Identifier(IdKind.ORG_NAME, "Example Media Ltd")))
    assert claims
    assert all("not evidence of wrongdoing" in x.raw.get("qualifier", "")
               for x in claims)


@pytest.mark.asyncio
async def test_offshore_leaks_records_it_is_a_snapshot_not_a_register():
    url = "https://offshoreleaks.icij.org/api/v1/search?q=Example%20Ltd"
    c = _mk("icij_offshore_leaks",
            _Fetcher(js={url: [{"node_id": "9", "name": "Example Ltd"}]}))
    claims = list(await c.collect(Identifier(IdKind.ORG_NAME, "Example Ltd")))
    assert any("leak disclosure" in x.raw.get("snapshot", "") for x in claims)


@pytest.mark.asyncio
async def test_offshore_leaks_absence_is_a_real_finding():
    """Unlike a coverage-less aggregator, ICIJ absence is meaningful."""
    c = _mk("icij_offshore_leaks", _Fetcher())
    claims = list(await c.collect(Identifier(IdKind.ORG_NAME, "Nobody Ltd")))
    assert claims[0].raw["absence_kind"] == "checked_absent"


# ---- chain activity -------------------------------------------------------- #

@pytest.mark.asyncio
async def test_chain_activity_does_not_claim_control():
    """On-chain data shows an address transacted, never who controls it."""
    addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    url = f"https://mempool.space/api/address/{addr}"
    c = _mk("chain_activity", _Fetcher(js={url: {"chain_stats": {"tx_count": 12}}}))
    claims = list(await c.collect(Identifier(IdKind.URL, f"btc:{addr}")))
    assert claims
    assert "does not establish who controls it" in claims[0].raw["limitation"]
    assert not [x for x in claims if x.object.kind is IdKind.PERSON_NAME]


@pytest.mark.asyncio
async def test_monero_is_reported_as_unqueryable_by_design():
    c = _mk("chain_activity", _Fetcher())
    claims = list(await c.collect(Identifier(IdKind.URL, "xmr:4Aabc")))
    assert claims and "by design" in claims[0].raw.get("note", "")


# ---- business directories -------------------------------------------------- #

@pytest.mark.asyncio
async def test_directory_results_are_corroborative_only():
    """Compiled from self-submission: an entry proves someone submitted it."""
    url = "https://www.infobel.com/en/world/search?name=Example+Media+Ltd"
    page = "<div>Example Media Ltd, 12 Example Street, CA 94105  +1 415 555 0100</div>"
    c = _mk("business_directory", _Fetcher({url: page}))
    claims = list(await c.collect(Identifier(IdKind.ORG_NAME, "Example Media Ltd")))
    assert all(x.reliability is Reliability.WEAK for x in claims)
    assert all("self-submitted" in x.raw.get("caveat", "") for x in claims)


# ---- source classification and policy -------------------------------------- #

def test_lookup_services_are_not_classified_as_data_brokers():
    """OPEN_DATASET, not DATA_BROKER — these index public web data rather than
    selling personal records, and misclassifying them would trip the deny path."""
    for n in ("reverse_publisher_id", "business_directory"):
        assert registry()[n].source_class is SourceClass.OPEN_DATASET


def test_registry_sources_are_classified_as_registries():
    for n in ("icij_offshore_leaks", "cninfo_disclosure", "chain_activity"):
        assert registry()[n].source_class is SourceClass.PUBLIC_REGISTRY


@pytest.mark.parametrize("source", [
    "blackbookonline.info", "openlinkprofiler.org", "dnsdumpster.com",
    "wipo.int/pct-contracting-states", "blockexplorer.com",
])
def test_deliberately_unautomated_sources_carry_their_reason(source):
    """The decision travels with the tool, so nobody re-litigates it from
    scratch or quietly adds a collector that policy excluded."""
    assert source in NOT_AUTOMATED
    assert len(NOT_AUTOMATED[source]) > 60


def test_blackbook_exclusion_matches_the_data_broker_policy():
    reason = NOT_AUTOMATED["blackbookonline.info"]
    assert "person" in reason.lower() and "manual" in reason.lower()


def test_cninfo_states_its_coverage_limit():
    """Listed companies only; most Chinese entities appear nowhere queryable."""
    import inspect

    src = inspect.getsource(registry()["cninfo_disclosure"])
    assert "listed" in src and "AMR" in src
