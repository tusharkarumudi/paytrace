"""The five registry and imprint collectors, driven directly.

All six network-touching collectors in `collectors/business.py` had no coverage
of their `collect` methods; only `ads_txt_owner` did. `sellers_json` is covered
in `test_sellers_json_collector.py`; these are the other five.

They are where the toolkit's judgment lives. Each one decides what a document
is allowed to mean -- whether a partial register match is the company asked
about, whether a sentence that DENIES a relationship is evidence of one,
whether a resigned officer is still an officer -- and every one of those
decisions was reached in response to a specific wrong answer. Untested, they
are a comment that happens to compile.

The fetcher is stubbed. Transport is covered in `test_net.py`; what was
untested is what these do with what comes back.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from attribution_graph import Identifier, IdKind, Predicate, Reliability

from paytrace.collectors.business import (
    CompaniesHouseUK,
    Gleif,
    Imprint,
    SecEdgar,
    Yente,
)


class _Fetcher:
    """Serves canned JSON and pages, and records what was asked for.

    `requests` matters as much as the return values: a collector that declines
    to search must be shown to have made no request, not merely to have
    returned nothing.
    """

    def __init__(self, json_routes=None, pages=None):
        self.json_routes = json_routes or {}
        self.pages = pages or {}
        self.requests: list[str] = []
        self.headers: list[dict | None] = []

    async def get_json(self, url, headers=None, **kw):
        self.requests.append(url)
        self.headers.append(headers)
        # Longest matching route wins. A plain "first substring match" let the
        # route for `lei-records/<lei>` also answer
        # `lei-records/<lei>/direct-parent`, so the stub invented an ownership
        # relationship the test never declared -- a stub that fabricates
        # evidence is worse than no stub.
        best = max((r for r in self.json_routes if r in url),
                   key=len, default=None)
        return self.json_routes[best] if best is not None else None

    async def get(self, url, **kw):
        self.requests.append(url)
        body = self.pages.get(url)
        if body is None:
            return None
        return type("R", (), {"url": url, "status": 200, "text": body})()


def _run(collector_cls, ident, fetcher):
    c = collector_cls(fetcher=fetcher, scope=object())
    return list(asyncio.run(c.collect(ident)))


# =========================================================================== #
# GLEIF
# =========================================================================== #

LEI = "EXAMPLELEI0000000001"

GLEIF_ENTITY = {
    "id": LEI,
    "attributes": {"entity": {
        "legalName": {"name": "Example Media Ltd"},
        "jurisdiction": "GB",
        "registeredAs": "09876543",
        "legalAddress": {"addressLines": ["1 Example Street"], "city": "London",
                         "region": "GB-LND", "postalCode": "EC1A 1AA",
                         "country": "GB"},
    }},
}


def test_gleif_rejects_a_partial_name_match():
    """`filter[entity.legalName]` is a PARTIAL match.

    Asking for "Example Media Ltd" returns anything merely containing part of
    it -- a French company literally named "LLC", an "Example Court, LLC LLC"
    -- and every one of those was once accepted as a claim and resolved as an
    entity of the case. The match is exact on the distinctive words.
    """
    other = json.loads(json.dumps(GLEIF_ENTITY))
    other["id"] = "EXAMPLELEI0000000002"
    other["attributes"]["entity"]["legalName"]["name"] = "Example Court, LLC LLC"
    f = _Fetcher({"lei-records?filter": {"data": [GLEIF_ENTITY, other]}})
    claims = _run(Gleif, Identifier(IdKind.ORG_NAME, "Example Media Ltd"), f)
    subjects = {c.subject.value for c in claims}
    assert subjects == {LEI}, "a partial match was accepted as the company"


def test_gleif_does_not_search_for_a_bare_legal_suffix():
    """Searching GLEIF for "INC" returns whichever company is called that."""
    f = _Fetcher({"lei-records": {"data": [GLEIF_ENTITY]}})
    assert _run(Gleif, Identifier(IdKind.ORG_NAME, "Inc"), f) == []
    assert f.requests == [], "a request was made for a name worth no search"


def test_gleif_an_lei_is_fetched_directly_not_searched():
    f = _Fetcher({f"lei-records/{LEI}": {"data": GLEIF_ENTITY}})
    claims = _run(Gleif, Identifier(IdKind.LEI, LEI), f)
    assert claims, "a direct LEI lookup produced nothing"
    assert not any("filter" in r for r in f.requests), "an LEI was searched for"


def test_gleif_emits_the_register_fields_as_authoritative_in_one_group():
    """Four facts from one register record must not corroborate each other.

    They share a correlation group so the scoring model counts the record once,
    however many fields it happened to carry.
    """
    f = _Fetcher({f"lei-records/{LEI}": {"data": GLEIF_ENTITY},
                  # No ownership tree declared, stated explicitly so the record
                  # route cannot answer for it.
                  f"lei-records/{LEI}/direct-parent": {},
                  f"lei-records/{LEI}/ultimate-parent": {}})
    claims = _run(Gleif, Identifier(IdKind.LEI, LEI), f)
    by_pred = {c.predicate: c for c in claims}
    assert by_pred[Predicate.LEGAL_NAME].object == Identifier(
        IdKind.ORG_NAME, "Example Media Ltd")
    assert by_pred[Predicate.INCORPORATED_IN].object == "GB"
    assert by_pred[Predicate.REGISTERED_ADDRESS].object == Identifier(
        IdKind.POSTAL_ADDRESS,
        "1 Example Street, London, GB-LND, EC1A 1AA, GB")
    # registeredAs is only meaningful with the jurisdiction that scopes it.
    assert by_pred[Predicate.SAME_AS].object == Identifier(
        IdKind.COMPANY_NUMBER, "GB/09876543")
    assert all(c.reliability is Reliability.AUTHORITATIVE for c in claims)
    groups = {c.correlation_group for c in claims}
    assert groups == {f"gleif|{LEI}"}


def test_gleif_registered_number_is_withheld_without_a_jurisdiction():
    """A bare company number is ambiguous across registers, so it is not a
    `SAME_AS` on its own."""
    rec = json.loads(json.dumps(GLEIF_ENTITY))
    del rec["attributes"]["entity"]["jurisdiction"]
    f = _Fetcher({f"lei-records/{LEI}": {"data": rec}})
    claims = _run(Gleif, Identifier(IdKind.LEI, LEI), f)
    assert Predicate.SAME_AS not in {c.predicate for c in claims}


def test_gleif_reads_the_ownership_tree_and_separates_the_two_relations():
    """Direct and ultimate parent are different facts from different documents,
    so they get their own groups rather than sharing the child's."""
    parent = "EXAMPLELEI0000000003"
    f = _Fetcher({
        f"lei-records/{LEI}/direct-parent": {"data": {"id": parent}},
        f"lei-records/{LEI}/ultimate-parent": {"data": {"id": parent}},
        f"lei-records/{LEI}": {"data": GLEIF_ENTITY},
    })
    claims = _run(Gleif, Identifier(IdKind.LEI, LEI), f)
    rels = [c for c in claims if c.predicate is Predicate.PARENT_OF]
    assert len(rels) == 2
    assert {c.raw["relationship"] for c in rels} == {"direct-parent",
                                                     "ultimate-parent"}
    assert {c.correlation_group for c in rels} == {
        f"gleif_rel|{LEI}|direct-parent", f"gleif_rel|{LEI}|ultimate-parent"}
    # The parent is the subject and the child the object: PARENT_OF, not owned.
    assert all(c.subject == Identifier(IdKind.LEI, parent) for c in rels)
    assert all(c.object == Identifier(IdKind.LEI, LEI) for c in rels)


def test_gleif_survives_an_empty_or_missing_response():
    assert _run(Gleif, Identifier(IdKind.LEI, LEI), _Fetcher()) == []


# =========================================================================== #
# SEC EDGAR
# =========================================================================== #

EDGAR_SUB = {
    "name": "Example Media Inc",
    "formerNames": [{"name": "Old Example Corp", "to": "2019-03-01T00:00:00.000Z"}],
    "stateOfIncorporation": "DE",
    "addresses": {"business": {"street1": "1 Example Ave", "city": "Dover",
                               "stateOrCountry": "DE", "zipCode": "19901"}},
    "website": "https://www.Example-Media.test/investors",
}


def test_edgar_marks_a_former_name_as_former():
    """A former name is evidence about the past.

    Emitted indistinguishably from the current name, it reads as an alias the
    company uses now -- which is how a renamed company gets reported under a
    name it has not used for years.
    """
    f = _Fetcher({"submissions/CIK": EDGAR_SUB})
    claims = _run(SecEdgar, Identifier(IdKind.CIK, "0000320193"), f)
    names = {c.object.value: c for c in claims
             if c.predicate is Predicate.LEGAL_NAME}
    assert names["Example Media Inc"].raw in (None, {}) or not (
        names["Example Media Inc"].raw or {}).get("former")
    former = names["Old Example Corp"]
    assert former.raw == {"former": True}
    assert former.observed_at is not None, "a former name with no date"
    assert former.observed_at.year == 2019


def test_edgar_normalises_a_website_to_a_bare_domain():
    """`https://www.Example-Media.test/investors` is not an identifier.

    A domain claim has to be the domain, or it will never join to the ads.txt
    evidence keyed on one.
    """
    f = _Fetcher({"submissions/CIK": EDGAR_SUB})
    claims = _run(SecEdgar, Identifier(IdKind.CIK, "0000320193"), f)
    domains = [c.object.value for c in claims
               if c.predicate is Predicate.OPERATES]
    assert domains == ["example-media.test"]


def test_edgar_states_incorporation_as_a_scoped_code():
    f = _Fetcher({"submissions/CIK": EDGAR_SUB})
    claims = _run(SecEdgar, Identifier(IdKind.CIK, "0000320193"), f)
    inc = next(c for c in claims if c.predicate is Predicate.INCORPORATED_IN)
    assert inc.object == "US-DE", "a bare 'DE' is Delaware or Germany"


def test_edgar_treats_two_spellings_of_one_cik_as_one_company():
    """The full-text index returns CIKs both as bare integers and zero-padded.

    Unnormalised, `320193` and `"0000320193"` survive the de-duplication as two
    entries: the same filer is fetched twice and, worse, becomes two CIK nodes
    in the graph, so one company's facts are split across two entities that
    never corroborate each other.

    Asserting only the request URL does not show this -- the URL is padded
    again when it is formatted -- so the identifier on the claim is what is
    checked. Found by planting the defect.
    """
    f = _Fetcher({
        "search-index": {"hits": {"hits": [
            {"_source": {"ciks": [320193, 320193]}},
            {"_source": {"ciks": ["0000320193"]}},
        ]}},
        "submissions/CIK": EDGAR_SUB,
    })
    claims = _run(SecEdgar, Identifier(IdKind.ORG_NAME, "Example Media"), f)
    subs = [r for r in f.requests if "submissions" in r]
    assert subs == ["https://data.sec.gov/submissions/CIK0000320193.json"], subs
    assert {c.subject for c in claims} == {
        Identifier(IdKind.CIK, "0000320193")}, "one filer became two nodes"


def test_edgar_skips_a_cik_with_no_submissions_document():
    f = _Fetcher({"search-index": {"hits": {"hits": [
        {"_source": {"ciks": [320193]}}]}}})
    assert _run(SecEdgar, Identifier(IdKind.ORG_NAME, "Example Media"), f) == []


# =========================================================================== #
# Imprint
# =========================================================================== #

def _page(body: str) -> str:
    return "<html><body>" + body + "</body></html>" + ("&nbsp;" * 60)


def test_imprint_does_not_read_a_name_out_of_a_disclaimer():
    """A viewer site's terms page says "not affiliated with <platform>, Inc."
    precisely to DENY the connection.

    Reading the name out of that sentence inverted its meaning and reported the
    disclaimer as evidence of the relationship -- the single worst inversion
    this collector can produce, because the sentence says the opposite.
    """
    body = _page(
        "<p>This site is not affiliated with, associated with, authorised by, "
        "endorsed by, or in any way officially connected with "
        "Northwind Platforms, Inc.</p>")
    f = _Fetcher(pages={"https://viewer.test/impressum": body})
    claims = _run(Imprint, Identifier(IdKind.DOMAIN, "viewer.test"), f)
    names = [c.object.value for c in claims
             if c.predicate is Predicate.LEGAL_NAME]
    assert names == [], f"a denial was read as a relationship: {names}"


def test_imprint_still_reads_a_name_that_is_not_disclaimed():
    """The suppression must not swallow the operator's own disclosure.

    An imprint commonly carries both: the operator's name, and a disclaimer
    about someone else's trademark.
    """
    body = _page(
        "<p>Operated by Example Media Ltd, London.</p>"
        "<p>Instagram is a trademark of Northwind Platforms, Inc.</p>")
    f = _Fetcher(pages={"https://viewer.test/impressum": body})
    claims = _run(Imprint, Identifier(IdKind.DOMAIN, "viewer.test"), f)
    names = [c.object.value for c in claims
             if c.predicate is Predicate.LEGAL_NAME]
    assert "Example Media Ltd" in names
    assert not any("Northwind" in n for n in names), names


def test_imprint_rejects_a_name_assembled_from_a_contact_form():
    """The entity pattern takes capitalised words before a legal suffix.

    A contact form next to a footer suffix yielded "Name Email Message Inc" --
    a company that does not exist, reported as the site naming its operator.
    """
    # One text run on purpose. Written with tags between the words
    # (`<label>Name</label>...<footer>Inc</footer>`) the pattern never matches
    # at all, because a tag is a boundary -- so the test passed with the
    # furniture guard removed, proving only the boundary rule that
    # `test_imprint_treats_a_tag_as_a_boundary_not_a_space` already covers.
    # Caught by planting the defect.
    body = _page("<p>Name Email Message Inc</p>")
    f = _Fetcher(pages={"https://viewer.test/impressum": body})
    claims = _run(Imprint, Identifier(IdKind.DOMAIN, "viewer.test"), f)
    names = [c.object.value for c in claims
             if c.predicate is Predicate.LEGAL_NAME]
    assert names == [], f"page furniture became a company: {names}"

    # A real name sitting in the same run is still read, so the guard is a
    # filter on furniture and not on multi-word names.
    ok = _page("<p>Operated by Example Media Ltd</p>")
    f2 = _Fetcher(pages={"https://viewer.test/impressum": ok})
    kept = [c.object.value for c in _run(
        Imprint, Identifier(IdKind.DOMAIN, "viewer.test"), f2)
        if c.predicate is Predicate.LEGAL_NAME]
    assert "Example Media Ltd" in kept, kept


def test_imprint_treats_a_tag_as_a_boundary_not_a_space():
    """Flattening tags to spaces let a name span unrelated elements."""
    body = _page("<td>Acme</td><td>Holdings Ltd</td>")
    f = _Fetcher(pages={"https://viewer.test/impressum": body})
    claims = _run(Imprint, Identifier(IdKind.DOMAIN, "viewer.test"), f)
    names = [c.object.value for c in claims
             if c.predicate is Predicate.LEGAL_NAME]
    assert "Acme Holdings Ltd" not in names, "a name crossed an element boundary"


def test_imprint_stops_at_the_first_page_that_yields_structure():
    """Ten paths against a site the subject controls is a lot of requests."""
    body = _page("<p>Operated by Example Media Ltd.</p>")
    f = _Fetcher(pages={"https://viewer.test/impressum": body,
                        "https://viewer.test/imprint": body})
    _run(Imprint, Identifier(IdKind.DOMAIN, "viewer.test"), f)
    assert f.requests == ["https://viewer.test/impressum"], f.requests


def test_imprint_ignores_a_page_too_short_to_be_a_notice():
    f = _Fetcher(pages={"https://viewer.test/impressum": "<html>hi</html>"})
    claims = _run(Imprint, Identifier(IdKind.DOMAIN, "viewer.test"), f)
    assert claims == []
    # It must keep trying the other paths rather than stopping at a stub page.
    assert len(f.requests) == len(Imprint.PATHS)


def test_imprint_findings_are_self_published_not_authoritative():
    """An imprint is the subject's own claim about itself."""
    body = _page("<p>Operated by Example Media Ltd. Contact: ops@viewer.test. "
                 "Company Number: 09876543</p>")
    f = _Fetcher(pages={"https://viewer.test/impressum": body})
    claims = _run(Imprint, Identifier(IdKind.DOMAIN, "viewer.test"), f)
    assert claims, "nothing was extracted from a full imprint"
    assert all(c.reliability is Reliability.MODERATE for c in claims)
    preds = {c.predicate for c in claims}
    assert Predicate.PROFILE_BINDING in preds, "the contact email was missed"
    assert Predicate.SAME_AS in preds, "the company number was missed"
    # The jurisdiction is genuinely unknown from an imprint, and says so.
    num = next(c for c in claims if c.predicate is Predicate.SAME_AS)
    assert num.object.value.startswith("unknown/")


def test_imprint_email_pattern_does_not_backtrack_catastrophically():
    """Unbounded quantifiers around the '@' took 170ms on a crafted 8KB run.

    The page belongs to the subject, so a pattern that degrades on crafted
    input is a denial of service against the analyst running the scrape.
    """
    import time

    hostile = "a" * 8000 + "@"
    start = time.monotonic()
    Imprint.EMAIL_RE.findall(hostile)
    assert time.monotonic() - start < 0.1, "the email pattern backtracks"


# =========================================================================== #
# Companies House UK
# =========================================================================== #

def test_companies_house_makes_no_request_without_a_key(monkeypatch):
    """A keyless run must be a silent skip, not an unauthenticated request."""
    monkeypatch.delenv("CH_API_KEY", raising=False)
    f = _Fetcher()
    assert _run(CompaniesHouseUK,
                Identifier(IdKind.ORG_NAME, "Example Media Ltd"), f) == []
    assert f.requests == []


def test_companies_house_refuses_a_company_number_from_another_register(
        monkeypatch):
    """`de/HRB12345` is not a UK company number.

    Sent to the UK register it either 404s or, worse, collides with an
    unrelated UK company that happens to share the digits.
    """
    monkeypatch.setenv("CH_API_KEY", "k")
    f = _Fetcher()
    assert _run(CompaniesHouseUK,
                Identifier(IdKind.COMPANY_NUMBER, "de/HRB12345"), f) == []
    assert f.requests == []


def test_companies_house_sends_basic_auth_with_an_empty_password(monkeypatch):
    """The API wants the key as the username and no password."""
    import base64

    monkeypatch.setenv("CH_API_KEY", "secret-key")
    f = _Fetcher({"persons-with-significant-control": {"items": []}})
    _run(CompaniesHouseUK, Identifier(IdKind.COMPANY_NUMBER, "gb/09876543"), f)
    assert f.headers, "no request was made"
    expected = base64.b64encode(b"secret-key:").decode()
    assert f.headers[0] == {"Authorization": f"Basic {expected}"}


def test_companies_house_types_a_corporate_owner_as_an_organisation(monkeypatch):
    """A PSC is often another company.

    Typed as a person, it goes to person-scoped handling and never joins to the
    corporate register entry that would carry it further.
    """
    monkeypatch.setenv("CH_API_KEY", "k")
    f = _Fetcher({"persons-with-significant-control": {"items": [
        {"name": "Jane Smith", "kind": "individual-person-with-significant-control",
         "notified_on": "2020-01-15",
         "natures_of_control": ["ownership-of-shares-75-to-100-percent"]},
        {"name": "Holdco Ltd", "kind": "corporate-entity-person-with-significant-control",
         "notified_on": "2021-06-01"},
    ]}})
    claims = _run(CompaniesHouseUK,
                  Identifier(IdKind.COMPANY_NUMBER, "gb/09876543"), f)
    kinds = {c.subject.value: c.subject.kind for c in claims}
    assert kinds["Jane Smith"] is IdKind.PERSON_NAME
    assert kinds["Holdco Ltd"] is IdKind.ORG_NAME
    jane = next(c for c in claims if c.subject.value == "Jane Smith")
    assert jane.predicate is Predicate.BENEFICIAL_OWNER_OF
    assert jane.object == Identifier(IdKind.COMPANY_NUMBER, "gb/09876543")
    assert jane.observed_at is not None and jane.observed_at.year == 2020
    assert jane.raw["natures_of_control"] == [
        "ownership-of-shares-75-to-100-percent"]


def test_companies_house_excludes_a_resigned_officer(monkeypatch):
    """A resigned director is not an officer of the company.

    Reported as current, it names someone as responsible for a company they
    left -- which is the kind of error that reaches a real person.
    """
    monkeypatch.setenv("CH_API_KEY", "k")
    f = _Fetcher({"officers": {"items": [
        {"name": "Current Director", "appointed_on": "2019-01-01",
         "officer_role": "director"},
        {"name": "Former Director", "appointed_on": "2015-01-01",
         "resigned_on": "2018-04-01", "officer_role": "director"},
    ]}})
    claims = _run(CompaniesHouseUK,
                  Identifier(IdKind.COMPANY_NUMBER, "gb/09876543"), f)
    officers = [c.subject.value for c in claims
                if c.predicate is Predicate.OFFICER_OF]
    assert officers == ["Current Director"], officers


@pytest.mark.parametrize("juris", ["gb", "uk", "unknown"])
def test_companies_house_accepts_the_jurisdictions_it_can_serve(monkeypatch, juris):
    """`unknown/` is included on purpose: an imprint company number has no
    jurisdiction, and the UK register is a reasonable place to try it."""
    monkeypatch.setenv("CH_API_KEY", "k")
    f = _Fetcher({"persons-with-significant-control": {"items": []}})
    _run(CompaniesHouseUK,
         Identifier(IdKind.COMPANY_NUMBER, f"{juris}/09876543"), f)
    assert f.requests, f"{juris} was refused"


# =========================================================================== #
# yente / OpenSanctions
# =========================================================================== #

def test_yente_discards_a_weak_fuzzy_match():
    """yente scores every candidate and will return remote ones.

    A 0.4 match on a company name is a different company, and emitted as
    SAME_AS it merges two unrelated entities into one node of the graph.
    """
    f = _Fetcher({"search/default": {"results": [
        {"id": "strong", "score": 0.95, "properties": {"name": ["Example Media Ltd"]}},
        {"id": "weak", "score": 0.4, "properties": {"name": ["Examploid Medial Ltd"]}},
    ]}})
    claims = _run(Yente, Identifier(IdKind.ORG_NAME, "Example Media Ltd"), f)
    assert {c.correlation_group for c in claims} == {"yente|strong"}


def test_yente_asks_for_the_schema_matching_the_identifier():
    """Searching the Person index for a company name returns noise."""
    f = _Fetcher({"search/default": {"results": []}})
    _run(Yente, Identifier(IdKind.ORG_NAME, "Example Media Ltd"), f)
    assert "schema=Company" in f.requests[0]
    f2 = _Fetcher({"search/default": {"results": []}})
    _run(Yente, Identifier(IdKind.PERSON_NAME, "Jane Smith"), f2)
    assert "schema=Person" in f2.requests[0]


def test_yente_rates_an_lei_above_a_name_alias():
    """A name alias is a fuzzy match; an LEI is an identifier.

    Banding them the same lets five spellings of one name carry the weight of a
    register identifier.
    """
    f = _Fetcher({"search/default": {"results": [{
        "id": "x", "score": 0.9, "datasets": ["gleif"],
        "properties": {"name": ["Example Media Ltd"],
                       "alias": ["Example Media Limited"],
                       "leiCode": [LEI]}}]}})
    claims = _run(Yente, Identifier(IdKind.ORG_NAME, "Example Media Ltd"), f)
    by_kind = {c.object.kind: c for c in claims}
    assert by_kind[IdKind.LEI].reliability is Reliability.STRONG
    assert by_kind[IdKind.ORG_NAME].reliability is Reliability.MODERATE
    # The score and the datasets travel with the claim: a 0.71 match and a 0.99
    # match are not the same evidence, and the reader has to be able to see it.
    alias = by_kind[IdKind.ORG_NAME]
    assert alias.raw["yente_score"] == 0.9
    assert alias.raw["datasets"] == ["gleif"]


def test_yente_caps_what_one_result_can_contribute():
    """An entity with forty aliases would otherwise dominate the graph."""
    f = _Fetcher({"search/default": {"results": [{
        "id": "x", "score": 0.9,
        "properties": {"name": [f"Alias {i}" for i in range(20)],
                       "leiCode": [f"EXAMPLELEI{i:010d}" for i in range(10)]}}]}})
    claims = _run(Yente, Identifier(IdKind.ORG_NAME, "Example Media Ltd"), f)
    assert len([c for c in claims if c.object.kind is IdKind.ORG_NAME]) == 5
    assert len([c for c in claims if c.object.kind is IdKind.LEI]) == 2


def test_yente_survives_an_unreachable_server():
    """The default is a localhost service that is usually not running."""
    assert _run(Yente, Identifier(IdKind.ORG_NAME, "Example Media Ltd"),
                _Fetcher()) == []


# =========================================================================== #
# The paths the five tests above left uncovered
# =========================================================================== #

def test_companies_house_searches_by_name_when_given_one(monkeypatch):
    """The name route is a different path from the company-number route.

    It was the only wholly uncovered branch left in this collector, and it is
    the one an investigation actually reaches: a name comes out of an imprint
    or a sellers.json long before a company number does.
    """
    monkeypatch.setenv("CH_API_KEY", "k")
    f = _Fetcher({
        "search/companies": {"items": [{"company_number": "09876543"}]},
        "officers": {"items": [{"name": "Jane Smith",
                                "appointed_on": "2019-01-01",
                                "officer_role": "director"}]},
    })
    claims = _run(CompaniesHouseUK,
                  Identifier(IdKind.ORG_NAME, "Example Media Ltd"), f)
    assert "q=Example+Media+Ltd" in f.requests[0], f.requests[0]
    assert [c.subject.value for c in claims] == ["Jane Smith"]
    # Whatever the search was given, the claim is keyed on the register's own
    # scoped number, not the name that found it.
    assert claims[0].object == Identifier(IdKind.COMPANY_NUMBER, "gb/09876543")


def test_companies_house_skips_a_register_entry_with_no_name(monkeypatch):
    """A PSC record can be present and suppressed, carrying no name.

    Emitted anyway it becomes an entity called `None`.
    """
    monkeypatch.setenv("CH_API_KEY", "k")
    f = _Fetcher({"persons-with-significant-control": {"items": [
        {"kind": "individual-person-with-significant-control"},
        {"name": "", "kind": "individual-person-with-significant-control"},
    ]}})
    assert _run(CompaniesHouseUK,
                Identifier(IdKind.COMPANY_NUMBER, "gb/09876543"), f) == []


def test_a_manager_domain_with_a_country_suffix_keeps_only_the_host():
    """The IAB spec allows `MANAGERDOMAIN=<domain>[, <cc>]`.

    `MANAGERDOMAIN=bcn.group, DE` must yield the domain `bcn.group`, not
    `bcn.group, DE` -- which is not a domain, joins to nothing, and was how a
    real manager went unresolved.
    """
    from paytrace.collectors.business import AdsTxtOwner

    page = ("OWNERDOMAIN=example-media.test\n"
            "MANAGERDOMAIN=bcn.group, DE\n"
            "google.com, pub-0000000000000314, DIRECT\n")
    f = _Fetcher(pages={"https://viewer.test/ads.txt": page})
    claims = _run(AdsTxtOwner, Identifier(IdKind.DOMAIN, "viewer.test"), f)
    by_pred = {c.predicate: c for c in claims}
    assert by_pred[Predicate.MANAGER_DOMAIN].object == Identifier(
        IdKind.DOMAIN, "bcn.group")
    assert by_pred[Predicate.OWNER_DOMAIN].object == Identifier(
        IdKind.DOMAIN, "example-media.test")
    # Both are the site's own assertions about itself, and are labelled so.
    for pred in (Predicate.OWNER_DOMAIN, Predicate.MANAGER_DOMAIN):
        assert by_pred[pred].raw["self_declared"] is True


def test_a_malformed_register_date_does_not_end_the_run():
    """Registers publish dates this toolkit did not anticipate.

    A `ValueError` out of date parsing would abort the whole collector and lose
    every claim gathered before it, so an unparseable date becomes "no date".
    """
    from paytrace.collectors.business import _parse_iso

    assert _parse_iso(None) is None
    assert _parse_iso("") is None
    assert _parse_iso("not a date") is None
    assert _parse_iso("15/01/2020") is None
    parsed = _parse_iso("2020-01-15")
    assert parsed is not None and parsed.year == 2020
    assert parsed.tzinfo is not None, "a naive datetime will not compare"


def test_a_single_word_candidate_is_not_a_company_name():
    """`_plausible_org_name` needs at least a name and a suffix.

    A bare "Inc" or "Ltd" reaching the entity pattern is a footer, not a
    disclosure.
    """
    from paytrace.collectors.business import _plausible_org_name

    assert not _plausible_org_name("Inc")
    assert not _plausible_org_name("")
    assert not _plausible_org_name(". Ltd")
    assert _plausible_org_name("Example Media Ltd")


def test_a_widely_duplicated_account_is_demoted_and_labelled_not_dropped():
    """A line present on thousands of domains identifies no one.

    It is recorded at zero weight rather than discarded: its presence is the
    reason a large file produced few leads, and silently dropping it leaves a
    reader wondering where the accounts went. The `demoted` note is what stops
    it being passed on as a clean indicator.
    """
    from paytrace.adstxt import BOILERPLATE_THRESHOLD
    from paytrace.collectors.business import AdsTxtOwner

    class _Index:
        """Reports one account as a network template, the other as distinctive."""

        def account_holders(self, adsystem, seller_id):
            return (BOILERPLATE_THRESHOLD + 1 if seller_id == "pub-template"
                    else 1)

    # Lower-case seller id on purpose: the parser normalises case, which is
    # not what this test is about.
    page = ("google.com, pub-template, DIRECT\n"
            "adrelay.example, 7kqmz2bxr4tnwp8ls, DIRECT\n")
    f = _Fetcher(pages={"https://viewer.test/ads.txt": page})
    f.index = _Index()
    claims = _run(AdsTxtOwner, Identifier(IdKind.DOMAIN, "viewer.test"), f)

    sellers = {c.object.value: c for c in claims
               if c.predicate is Predicate.SELLER_OF}
    template = sellers["google.com/pub-template"]
    distinctive = sellers["adrelay.example/7kqmz2bxr4tnwp8ls"]

    assert template.weight == 0.0, "a template line carried scoring weight"
    assert template.raw["demoted"] == "widely duplicated template line"
    assert template.raw["account_class"] == "boilerplate"
    assert template.raw["holders"] == BOILERPLATE_THRESHOLD + 1

    assert distinctive.weight == 1.0
    assert "demoted" not in distinctive.raw, "a distinctive account was demoted"


def test_the_file_summary_says_why_a_large_file_yielded_few_leads():
    """A zero-weight note, recorded so the reader can see the shape of the file.

    Without it a 200-record ads.txt that produced two usable accounts looks
    like a failed run rather than a file of pasted network templates. It is
    `UNCERTAIN` at weight 0 on purpose: it is context about the document, not
    evidence about the operator.
    """
    from paytrace.collectors.business import AdsTxtOwner

    page = ("OWNERDOMAIN=example-media.test\n"
            "google.com, pub-template, DIRECT\n"
            "adrelay.example, 7kqmz2bxr4tnwp8ls, DIRECT\n")
    f = _Fetcher(pages={"https://viewer.test/ads.txt": page})
    f.index = type("I", (), {"account_holders": lambda self, a, s: 1})()
    claims = _run(AdsTxtOwner, Identifier(IdKind.DOMAIN, "viewer.test"), f)

    summary = next(c for c in claims if isinstance(c.object, str)
                   and c.object.startswith("ads_txt_summary:"))
    assert summary.weight == 0.0, "file context carried scoring weight"
    assert summary.reliability is Reliability.UNCERTAIN
    assert "discriminating" in summary.object
    # The OWNERDOMAIN note is the one that matters most in the summary.
    assert any("OWNERDOMAIN=example-media.test" in n
               for n in summary.raw["notes"]), summary.raw["notes"]
    assert summary.raw["resource"] == "ads_txt"
