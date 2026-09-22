"""Expansion from a resolved name.

The gap: resolving a payee to an individual used to be a dead end. PERSON_NAME
was accepted by one collector (sanctions screening), and `sellers_for_name`
existed but nothing called it.
"""

import pytest
from attribution_graph import IdKind, Predicate

from paytrace.enrich import (
    ROUTES_FOR,
    Route,
    expand_from_name,
    name_variants,
    person_routes_available,
)
from paytrace.sellersjson import SellerNameKind


class _Index:
    """Corpus where one person holds two publisher accounts."""

    SELLERS = {
        "tran thi binh": [("google.com", "pub-9000000000000001", ""),
                           ("pubmatic.com", "156423", "example.test")],
    }
    SITES = {
        ("google.com", "pub-9000000000000001"): ["operator-site.example", "sister-site.example"],
        ("pubmatic.com", "156423"): ["third-site.example"],
    }

    def sellers_for_name(self, name):
        return self.SELLERS.get(name.strip().lower(), [])

    def sites_for_seller(self, adsystem, seller_id):
        return self.SITES.get((adsystem, seller_id), [])


class _Fetcher:
    def __init__(self, routes=None):
        self.routes = routes or {}

    async def get(self, url, headers=None, allow_html=False):
        body = self.routes.get(url)

        class R:
            status = 200 if body else 404
            text = body or ""
        return R()

    async def get_json(self, url, headers=None):
        return None


# ---- name variants --------------------------------------------------------- #

def test_variants_cover_diacritics_and_initials():
    """Delegates to attribution_graph.lookup_variants -- the canonical
    implementation. Two versions previously drifted: 400 forms vs 7, overlap 1."""
    v = [x.lower() for x in name_variants("TRẦN THỊ BÌNH")]
    assert "trần thị bình" in v          # original preserved, always first
    assert "tran thi binh" in v          # diacritics folded
    assert any(x.startswith("t. t.") or x.startswith("t t") for x in v)


def test_name_variants_is_not_reimplemented_locally():
    from attribution_graph import lookup_variants
    assert name_variants("Müller") == lookup_variants("Müller", 12)


def test_lookup_variants_exclude_speculative_forms():
    """Matching casts a wide net; querying spends a request per form."""
    v = [x.lower() for x in name_variants("TRẦN THỊ BÌNH")]
    assert not any(x.startswith("al-") for x in v)
    assert len(v) <= 12


def test_variants_are_stable_and_deduplicated():
    a = name_variants("Example Media Ltd")
    assert a == name_variants("Example Media Ltd")
    assert len(a) == len(set(a))


def test_empty_name_yields_no_variants():
    assert name_variants("") == []


# ---- layering -------------------------------------------------------------- #
#
# Generation itself is tested in handle-correlation, which owns it. What is
# asserted here is that paytrace does not carry a second copy.

def test_handle_generation_lives_in_handle_correlation():
    """Handle formation is that module's subject. A second implementation in a
    collector package would drift, as name variation already had."""
    import paytrace
    assert not hasattr(paytrace, "handle_candidates")


# ---- routing by entity type ------------------------------------------------ #

def test_corporate_registries_are_skipped_for_a_natural_person():
    """Running them produces a 'checked, no match' line that reads as evidence
    when it is a category error."""
    assert Route.CORPORATE_REGISTRY not in ROUTES_FOR[SellerNameKind.NATURAL_PERSON]
    assert Route.CORPORATE_REGISTRY in ROUTES_FOR[SellerNameKind.ORGANIZATION]


def test_person_specific_routes_are_not_run_for_a_company():
    assert Route.PGP not in ROUTES_FOR[SellerNameKind.ORGANIZATION]
    assert Route.HANDLE_CANDIDATES not in ROUTES_FOR[SellerNameKind.ORGANIZATION]


def test_reverse_sellers_runs_for_both_types():
    for kind in (SellerNameKind.NATURAL_PERSON, SellerNameKind.ORGANIZATION):
        assert Route.REVERSE_SELLERS in ROUTES_FOR[kind]


# ---- the highest-yield route ----------------------------------------------- #

@pytest.mark.asyncio
async def test_reverse_sellers_recovers_the_whole_estate():
    """One payee record expands to every account and every authorising site."""
    exp = await expand_from_name("TRẦN THỊ BÌNH", index=_Index())

    assert "google.com/pub-9000000000000001" in exp.discovered["seller accounts"]
    assert "pubmatic.com/156423" in exp.discovered["seller accounts"]
    sites = exp.discovered["authorising sites"]
    assert {"operator-site.example", "sister-site.example", "third-site.example"} <= set(sites)


@pytest.mark.asyncio
async def test_reverse_sellers_matches_on_a_folded_variant():
    """The corpus holds 'tran thi binh'; the payee record has diacritics."""
    exp = await expand_from_name("TRẦN THỊ BÌNH", index=_Index())
    via = [c for c in exp.claims if c.raw.get("matched_variant")]
    assert via and via[0].raw["matched_variant"].lower() == "tran thi binh"


@pytest.mark.asyncio
async def test_missing_index_is_reported_as_not_run_not_as_empty():
    exp = await expand_from_name("TRẦN THỊ BÌNH")
    reasons = dict(exp.empty)
    assert Route.REVERSE_SELLERS in reasons
    assert "did not run" in reasons[Route.REVERSE_SELLERS]


@pytest.mark.asyncio
async def test_no_matching_seller_distinguishes_absence_from_coverage():
    exp = await expand_from_name("Nobody Here", index=_Index())
    reasons = dict(exp.empty)
    assert "corpus does not cover" in reasons[Route.REVERSE_SELLERS]


# ---- document search -------------------------------------------------------- #

@pytest.mark.asyncio
async def test_document_search_finds_the_name_and_colocated_emails():
    page = ("<html><body><p>Operated by Tran Thi Binh.</p>"
            "<p>Contact: legal@example.test or dmca@example.test</p></body></html>")
    f = _Fetcher({"https://operator-site.example/terms-of-service": page})
    exp = await expand_from_name("TRẦN THỊ BÌNH", fetcher=f, index=_Index(),
                                 known_domains=["operator-site.example"])
    assert "https://operator-site.example/terms-of-service" in exp.discovered[
        "documents naming the subject"]
    assert "legal@example.test" in exp.discovered["emails"]


@pytest.mark.asyncio
async def test_document_search_reports_empty_when_the_name_is_absent():
    f = _Fetcher({"https://operator-site.example/terms": "<p>nothing relevant</p>"})
    exp = await expand_from_name("TRẦN THỊ BÌNH", fetcher=f, index=_Index(),
                                 known_domains=["operator-site.example"])
    assert any(r is Route.DOCUMENT_SEARCH for r, _ in exp.empty)


# ---- claims ----------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_person_subject_is_typed_as_a_person():
    exp = await expand_from_name("TRẦN THỊ BÌNH", index=_Index())
    assert exp.kind is SellerNameKind.NATURAL_PERSON
    assert all(c.subject.kind is IdKind.PERSON_NAME for c in exp.claims
               if c.predicate is not Predicate.CONTRADICTS)


@pytest.mark.asyncio
async def test_company_subject_is_typed_as_an_organization():
    exp = await expand_from_name("Example Media Holdings Ltd", index=_Index())
    assert exp.kind is SellerNameKind.ORGANIZATION
    assert all(c.subject.kind is IdKind.ORG_NAME for c in exp.claims
               if c.predicate is not Predicate.CONTRADICTS)


@pytest.mark.asyncio
async def test_expansion_records_not_checked_for_the_corporate_route():
    """A person absent from GLEIF is a category error, not a finding."""
    exp = await expand_from_name("TRẦN THỊ BÌNH", index=_Index())
    absence = [c for c in exp.claims if c.predicate is Predicate.CONTRADICTS]
    assert absence
    assert absence[0].raw["absence_kind"] == "not_checked"
    assert absence[0].weight == 0.0


@pytest.mark.asyncio
async def test_render_separates_found_empty_and_not_applicable():
    exp = await expand_from_name("TRẦN THỊ BÌNH", index=_Index())
    out = exp.render()
    assert "seller accounts" in out
    assert "not applicable" in out
    assert "corporate registries hold no record" in out


# ---- honesty about installed routes ---------------------------------------- #

def test_uninstalled_routes_are_reported_as_not_run():
    from paytrace.collectors import registry

    avail = person_routes_available(registry())
    assert avail["dmca_agent"] is True
    assert person_routes_available([])["dmca_agent"] is False


def test_person_name_now_has_real_routes():
    """Was one collector (sanctions screening). Now several."""
    from paytrace.collectors import registry

    accepting = [n for n, c in registry().items()
                 if IdKind.PERSON_NAME in getattr(c, "accepts", ())]
    assert len(accepting) >= 3
    assert "dmca_agent" in accepting
