"""Expansion from a resolved name.

The investigation used to stop where it should start. Resolving
``google.com/pub-…`` to a payee name is the hard part; the name is then a key
into everything the operator has published under it, and nothing was using it.

An audit showed why:

    org_name      accepted by 11 collectors
    person_name   accepted by  1  (sanctions screening, which almost never hits)

So a natural person — which is what an individual AdSense publisher is — hit a
dead end the moment it was found. Corporate registries hold nothing for them,
and reporting "checked GLEIF, no match" made that look like a finding rather
than a category error.

## What a name is actually good for

**Reverse `sellers.json` by name is the highest-yield pivot and was unused.**
One person can hold several publisher accounts across several ad systems, each
authorised by a different set of domains. Going name → accounts → domains
recovers the whole estate from one payee record, and the corpus index already
supported the lookup.

After that, the routes differ by entity type, and conflating them wastes budget:

| Route | Person | Company |
|---|---|---|
| Reverse sellers.json | yes | yes |
| Corporate registries | **no** | yes |
| DMCA designated agent | yes | yes |
| Trademark | rarely | yes |
| PGP keyservers | yes | no |
| Package registries | yes | yes |
| Code hosts | yes | yes |
| Handle candidates | yes | no |

## Negative results are recorded, not implied

Every route that runs and returns nothing is recorded as checked-and-empty, with
its coverage. "GLEIF holds no record" means something entirely different for a
Vietnamese sole operator than for a UK company, and a report that does not
distinguish them is misleading in the direction of over-confidence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum

from attribution_graph import (
    AbsenceKind,
    Claim,
    Identifier,
    IdKind,
    Predicate,
    Reliability,
    absence_claim,
)

from .sellersjson import SellerNameKind, classify_seller_name


class Route(StrEnum):
    REVERSE_SELLERS = "reverse_sellers_json"
    CORPORATE_REGISTRY = "corporate_registry"
    DMCA = "dmca_agent"
    TRADEMARK = "trademark"
    PGP = "pgp_keyserver"
    PACKAGE_REGISTRY = "package_registry"
    CODE_HOST = "code_host"
    HANDLE_CANDIDATES = "handle_candidates"
    DOCUMENT_SEARCH = "document_search"


#: Which routes are worth running for which entity type. Running corporate
#: registries against a natural person burns budget and produces a
#: "checked, no match" line that reads as evidence when it is a category error.
ROUTES_FOR: dict[SellerNameKind, list[Route]] = {
    SellerNameKind.NATURAL_PERSON: [
        Route.REVERSE_SELLERS, Route.DMCA, Route.PGP, Route.PACKAGE_REGISTRY,
        Route.CODE_HOST, Route.HANDLE_CANDIDATES, Route.DOCUMENT_SEARCH,
    ],
    SellerNameKind.ORGANIZATION: [
        Route.REVERSE_SELLERS, Route.CORPORATE_REGISTRY, Route.DMCA,
        Route.TRADEMARK, Route.PACKAGE_REGISTRY, Route.CODE_HOST,
        Route.DOCUMENT_SEARCH,
    ],
    SellerNameKind.AMBIGUOUS: [
        Route.REVERSE_SELLERS, Route.CORPORATE_REGISTRY, Route.DMCA,
        Route.PACKAGE_REGISTRY, Route.CODE_HOST, Route.DOCUMENT_SEARCH,
    ],
}


# --------------------------------------------------------------------------- #
# Name variants
# --------------------------------------------------------------------------- #

def name_variants(name: str, limit: int = 12) -> list[str]:
    """Forms to query registries and indexes with.

    Delegates to ``attribution_graph.lookup_variants``, which is the canonical
    implementation. This module previously had its own, and the two drifted:
    the core produced 400 matching forms, this one produced 7, and they
    overlapped on 1. A lookup silently using the weaker set misses records the
    other would find.

    The core distinguishes lookup-safe rules (transliteration schemes,
    diacritic folding, name ordering) from matching-only ones (speculative
    vowel and consonant substitutions), because a query spends a request per
    form and a wrong form collides with a real person.
    """
    from attribution_graph import lookup_variants

    return lookup_variants(name, limit)


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #

@dataclass
class Expansion:
    name: str
    kind: SellerNameKind
    routes_run: list[Route] = field(default_factory=list)
    routes_skipped: list[tuple[Route, str]] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    discovered: dict[str, list[str]] = field(default_factory=dict)
    empty: list[tuple[Route, str]] = field(default_factory=list)

    def add(self, bucket: str, value: str) -> None:
        vals = self.discovered.setdefault(bucket, [])
        if value not in vals:
            vals.append(value)

    @property
    def total_discovered(self) -> int:
        return sum(len(v) for v in self.discovered.values())

    def render(self) -> str:
        L = [f"Expansion from {self.kind.value}: {self.name}", ""]
        if self.discovered:
            for bucket, values in sorted(self.discovered.items()):
                L.append(f"  {bucket} ({len(values)})")
                for v in values[:12]:
                    L.append(f"    {v}")
        else:
            L.append("  nothing discovered")
        if self.empty:
            L += ["", "  checked and empty:"]
            for route, why in self.empty:
                L.append(f"    {route.value}: {why}")
        if self.routes_skipped:
            L += ["", "  not applicable:"]
            for route, why in self.routes_skipped:
                L.append(f"    {route.value}: {why}")
        return "\n".join(L)


# --------------------------------------------------------------------------- #
# Expansion
# --------------------------------------------------------------------------- #

async def expand_from_name(
    name: str,
    *,
    fetcher=None,
    index=None,
    known_domains: Iterable[str] = (),
    source_url: str = "",
) -> Expansion:
    """Fan out from a resolved name across every applicable route."""
    kind = classify_seller_name(name)
    exp = Expansion(name=name, kind=kind)
    subject_kind = (IdKind.PERSON_NAME
                    if kind is SellerNameKind.NATURAL_PERSON else IdKind.ORG_NAME)
    subject = Identifier(subject_kind, name)
    variants = name_variants(name)
    routes = ROUTES_FOR[kind]

    for route in Route:
        if route not in routes:
            exp.routes_skipped.append((
                route,
                "corporate registries hold no record for a natural person"
                if route is Route.CORPORATE_REGISTRY else
                "not applicable to this entity type"))

    # ---- reverse sellers.json: the highest-yield route --------------------- #
    #
    # Capability-checked rather than assumed. Any object can be passed as an
    # index -- a fixture, an in-memory selectivity source, a partial corpus --
    # and only a full AdsTxtIndex supports the reverse lookups. Assuming the
    # shape raised AttributeError mid-run and lost the whole investigation.
    has_reverse = index is not None and all(
        callable(getattr(index, m, None))
        for m in ("sellers_for_name", "sites_for_seller"))

    if Route.REVERSE_SELLERS in routes and has_reverse:
        exp.routes_run.append(Route.REVERSE_SELLERS)
        found = 0
        for variant in variants:
            for adsystem, seller_id, domain in index.sellers_for_name(variant):
                found += 1
                acct = f"{adsystem}/{seller_id}"
                exp.add("seller accounts", acct)
                exp.claims.append(Claim(
                    subject=subject, predicate=Predicate.OPERATES,
                    object=Identifier(IdKind.SELLER_ID, acct),
                    collector="expand:reverse_sellers_json",
                    source_url=f"index://sellers/{variant}",
                    reliability=Reliability.STRONG,
                    correlation_group=f"reverse_sellers|{name}",
                    raw={"matched_variant": variant}))
                if domain:
                    exp.add("declared domains", domain)
                for site in index.sites_for_seller(adsystem, seller_id):
                    exp.add("authorising sites", site)
                    exp.claims.append(Claim(
                        subject=subject, predicate=Predicate.OPERATES,
                        object=Identifier(IdKind.DOMAIN, site),
                        collector="expand:reverse_sellers_json",
                        source_url=f"index://seller/{acct}",
                        reliability=Reliability.MODERATE,
                        correlation_group=f"reverse_sellers|{acct}",
                        raw={"via": acct}))
        if not found:
            exp.empty.append((
                Route.REVERSE_SELLERS,
                "no other publisher account in the corpus carries this name — "
                "either a single-account operator, or the corpus does not cover "
                "the ad systems they use"))
    elif Route.REVERSE_SELLERS in routes:
        exp.empty.append((
            Route.REVERSE_SELLERS,
            "no corpus index supplied; this is the highest-yield route and it "
            "did not run" if index is None else
            "the supplied index does not support reverse name lookup "
            "(needs sellers_for_name and sites_for_seller); build one with "
            "`paytrace-index build`"))

    # ---- handle candidates ------------------------------------------------- #
    # Generation lives in handle-correlation, which is where handle formation is
    # the subject. Soft-imported so paytrace does not hard-depend on a sibling.
    if Route.HANDLE_CANDIDATES in routes:
        try:
            from handle_correlation import candidates_from_name
        except ImportError:
            exp.empty.append((
                Route.HANDLE_CANDIDATES,
                "handle-correlation is not installed; install it or use "
                "attribution-suite to enable this route"))
        else:
            exp.routes_run.append(Route.HANDLE_CANDIDATES)
            for h in candidates_from_name(name):
                exp.add("handle candidates (leads only)", h)

    # ---- name variants for downstream lookups ------------------------------ #
    for v in variants:
        exp.add("name variants", v)

    # ---- document search across known properties --------------------------- #
    can_fetch = fetcher is not None and (
        callable(getattr(fetcher, "get", None))
        or callable(getattr(fetcher, "get_text", None)))

    if Route.DOCUMENT_SEARCH in routes and can_fetch:
        exp.routes_run.append(Route.DOCUMENT_SEARCH)
        hits = await _document_search(fetcher, name, variants, known_domains, exp,
                                      subject)
        if not hits:
            exp.empty.append((
                Route.DOCUMENT_SEARCH,
                f"name not present in the legal pages of "
                f"{len(list(known_domains))} known domain(s)"))
    elif Route.DOCUMENT_SEARCH in routes:
        exp.empty.append((
            Route.DOCUMENT_SEARCH,
            "no usable fetcher supplied; this route did not run"))

    # ---- negative evidence for the corporate route ------------------------- #
    if kind is SellerNameKind.NATURAL_PERSON:
        exp.claims.append(absence_claim(
            subject, "gleif", AbsenceKind.NOT_CHECKED,
            query_url=source_url or "n/a",
            what_was_sought="corporate registration"))

    return exp


#: Pages where an operator's legal identity most often appears.
_LEGAL_PATHS = (
    "/terms-of-service", "/terms", "/tos", "/privacy-policy", "/privacy",
    "/about", "/about-us", "/contact", "/impressum", "/legal", "/disclaimer",
    "/dmca", "/copyright",
)
_EMAIL = re.compile(r"[\w.+\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,4}")


async def _fetch_text(fetcher, url: str) -> str | None:
    """Retrieve a page through whichever fetcher protocol was supplied.

    Two exist in this toolchain and they are not interchangeable:

        collectors   async  ``get(url) -> Response``   (.status, .text)
        agent tools  sync   ``get_text(url) -> str | None``

    Assuming either one raised AttributeError mid-run and lost the whole
    investigation. Supporting both here is the pragmatic fix; unifying the
    protocols is the correct one and is tracked as an open item.
    """
    getter = getattr(fetcher, "get", None)
    if callable(getter):
        r = getter(url, allow_html=True)
        if hasattr(r, "__await__"):
            r = await r
        if r is None or getattr(r, "status", 0) != 200:
            return None
        return getattr(r, "text", None) or None

    get_text = getattr(fetcher, "get_text", None)
    if callable(get_text):
        out = get_text(url)
        if hasattr(out, "__await__"):
            out = await out
        return out or None

    return None


async def _document_search(fetcher, name, variants, known_domains, exp,
                           subject) -> int:
    """Look for the name in the legal pages of properties already attributed.

    A name found in `sellers.json` frequently reappears in a terms or DMCA page
    alongside an address or a second address — the operator wrote both, but only
    one of them was indexed.
    """
    hits = 0
    needles = [v.lower() for v in variants]

    for domain in list(known_domains)[:12]:
        for path in _LEGAL_PATHS:
            url = f"https://{domain}{path}"
            body = await _fetch_text(fetcher, url)
            if not body:
                continue
            text = re.sub(r"<[^>]+>", " ", body)
            flat = re.sub(r"\s+", " ", text).lower()

            if any(n in flat for n in needles):
                hits += 1
                exp.add("documents naming the subject", url)
                exp.claims.append(Claim(
                    subject=subject, predicate=Predicate.OPERATES,
                    object=Identifier(IdKind.URL, url),
                    collector="expand:document_search", source_url=url,
                    reliability=Reliability.MODERATE,
                    correlation_group=f"document|{domain}",
                    raw={"basis": "subject name present in a legal page"}))

                for em in list(dict.fromkeys(_EMAIL.findall(text)))[:5]:
                    low = em.lower()
                    if low.endswith(("example.com", "w3.org", "schema.org")):
                        continue
                    exp.add("emails", low)
                    exp.claims.append(Claim(
                        subject=subject, predicate=Predicate.PROFILE_BINDING,
                        object=Identifier(IdKind.EMAIL, low),
                        collector="expand:document_search", source_url=url,
                        reliability=Reliability.MODERATE,
                        correlation_group=f"document|{domain}",
                        raw={"co_located_with_name": True}))
                break
    return hits


# --------------------------------------------------------------------------- #
# Name-accepting collectors
# --------------------------------------------------------------------------- #

def person_routes_available(registry_names: Iterable[str]) -> dict[str, bool]:
    """Which person-productive collectors are installed.

    Used to report honestly: a route that is not installed did not return
    nothing, it did not run.
    """
    names = set(registry_names)
    return {
        "reverse_sellers_json": True,            # index-backed, always available
        "dmca_agent": "dmca_agent" in names,
        "pgp_wkd": "pgp_wkd" in names,
        "package_registry": "package_registry" in names,
        "code_host_org": "code_host_org" in names,
        "extension_store_developer": "extension_store_developer" in names,
    }
