"""Property and land records: corporate asset tracing.

**Entity-keyed by construction.** These collectors accept an owning legal entity
and return the parcels it holds. They do not accept a natural-person name, and
the module raises if handed one.

The reason is specific rather than general. A property record keyed on a company
answers "what does this shell own", which is the question in asset tracing,
sanctions work and real-estate fraud. The identical query keyed on a person's
name returns their home address. Same dataset, same API call, entirely different
artifact -- and the second one has no investigative use that the first does not
already serve.

When a parcel's owner of record *is* a natural person, that is analytically
meaningful: it means the ownership chain terminates and is not a shell. The
collectors record that fact -- ``chain_terminates_natural_person`` -- without
emitting the name or the address. The signal survives; the dossier does not.

Coverage is honest about being poor. US land records live in ~3,100 county
offices with no common schema; a minority publish open data and the rest are
captcha-gated or vendor-hosted. See ``catalog.py`` for what must be searched by
hand.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime, timezone

from attribution_graph import Claim, Identifier, IdKind, Predicate, Reliability, SourceClass

from .base import Collector, register


class PersonKeyedQueryRefused(ValueError):
    """Raised when a land-records collector is handed a natural-person name."""


#: Legal-form tokens indicating the owner of record is an entity, not a person.
ENTITY_FORM = re.compile(
    r"\b(LLC|L\.L\.C|INC|INCORPORATED|CORP|CORPORATION|CO|COMPANY|LTD|LIMITED|"
    r"LP|LLP|LLLP|PLC|TRUST|TR|FOUNDATION|HOLDINGS?|PARTNERS?|PARTNERSHIP|"
    r"ASSOCIATES|PROPERTIES|REALTY|VENTURES?|GROUP|ENTERPRISES?|GMBH|B\.?V|"
    r"N\.?V|S\.?A|PTE|PVT|SARL|AB|AS|OY|APS)\b",
    re.I,
)


def is_entity_name(name: str) -> bool:
    """Whether an owner-of-record string denotes an organization.

    Conservative: unmatched names are treated as natural persons and suppressed.
    A false negative costs one lead; a false positive publishes a home address.
    """
    return bool(ENTITY_FORM.search(name or ""))


class LandRecordCollector(Collector):
    """Base class enforcing the entity-keyed constraint."""

    accepts = (IdKind.ORG_NAME, IdKind.COMPANY_NUMBER)

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        if ident.kind in (IdKind.PERSON_NAME, IdKind.EMAIL, IdKind.HANDLE):
            raise PersonKeyedQueryRefused(
                f"{self.name} is entity-keyed. Querying land records by natural-person "
                "identifier returns a residential address and is not supported."
            )
        return await self.collect_for_entity(ident)

    async def collect_for_entity(self, ident: Identifier) -> Iterable[Claim]:
        raise NotImplementedError

    def owner_claims(
        self, parcel: Identifier, owner_name: str, source_url: str, group: str,
        observed_at: datetime | None = None,
    ) -> list[Claim]:
        """Emit ownership evidence, or a terminal marker for person-owned parcels."""
        if not is_entity_name(owner_name):
            return [self.claim(
                parcel, Predicate.OPERATES, "chain_terminates_natural_person",
                source_url, reliability=Reliability.AUTHORITATIVE,
                correlation_group=group, observed_at=observed_at,
                raw={"suppressed": "owner of record is a natural person; "
                                   "name and address withheld by policy"},
            )]
        return [self.claim(
            Identifier(IdKind.ORG_NAME, owner_name), Predicate.OPERATES,
            parcel, source_url, reliability=Reliability.AUTHORITATIVE,
            correlation_group=group, observed_at=observed_at,
        )]


# --------------------------------------------------------------------------- #
# NYC ACRIS  (Socrata, open, no key)
# --------------------------------------------------------------------------- #

@register
class NycAcris(LandRecordCollector):
    """NYC property transaction parties. Open Socrata endpoint, no key.

    High yield for real-estate shell structures: deed and mortgage parties are
    named, and LLC layering in Manhattan and Brooklyn is dense enough that one
    entity name often surfaces an entire portfolio.
    """

    name = "nyc_acris"
    source_class = SourceClass.PUBLIC_REGISTRY
    priority = 4

    PARTIES = "https://data.cityofnewyork.us/resource/636b-3b5g.json"

    async def collect_for_entity(self, ident: Identifier) -> Iterable[Claim]:
        if ident.kind is not IdKind.ORG_NAME or len(ident.value) < 5:
            return []
        name = ident.value.upper().replace("'", "")
        url = f"{self.PARTIES}?$where=upper(name)%20like%20'%25{name.replace(' ', '%20')}%25'&$limit=50"  # noqa: E501
        rows = await self.fetcher.get_json(url)
        if not isinstance(rows, list):
            return []

        claims: list[Claim] = []
        for row in rows:
            doc_id = row.get("document_id")
            owner = (row.get("name") or "").strip()
            if not (doc_id and owner):
                continue
            parcel = Identifier(IdKind.URL, f"acris:{doc_id}")
            claims.extend(self.owner_claims(
                parcel, owner, url,
                group=f"acris|{doc_id}",
                observed_at=_iso(row.get("good_through_date")),
            ))
            addr = ", ".join(filter(None, [
                row.get("address_1"), row.get("address_2"), row.get("city"),
                row.get("state"), row.get("zip"),
            ]))
            # Party address is only emitted for entity owners -- for a natural
            # person this field is a home address.
            if addr and is_entity_name(owner):
                claims.append(self.claim(
                    Identifier(IdKind.ORG_NAME, owner), Predicate.REGISTERED_ADDRESS,
                    Identifier(IdKind.POSTAL_ADDRESS, addr), url,
                    reliability=Reliability.STRONG,
                    correlation_group=f"acris|{doc_id}",
                ))
        return claims


# --------------------------------------------------------------------------- #
# HM Land Registry - overseas companies owning UK property
# --------------------------------------------------------------------------- #

@register
class UkOverseasProperty(LandRecordCollector):
    """UK property held by overseas companies.

    The cleanest asset-tracing source that exists, because the dataset is
    corporate-only by construction -- there is no natural-person exposure to
    manage. Requires the bulk CSV, which is free but registration-gated.

        paytrace-index landreg --csv OCOD_FULL_*.csv --db paytrace.sqlite
    """

    name = "uk_overseas_property"
    source_class = SourceClass.PUBLIC_REGISTRY
    priority = 5

    async def collect_for_entity(self, ident: Identifier) -> Iterable[Claim]:
        idx = getattr(self, "index", None)
        if idx is None or ident.kind is not IdKind.ORG_NAME:
            return []
        rows = idx.titles_for_proprietor(ident.value)
        claims: list[Claim] = []
        for title_no, country, price, date in rows:
            parcel = Identifier(IdKind.URL, f"hmlr:{title_no}")
            group = f"hmlr|{title_no}"
            claims.append(self.claim(
                ident, Predicate.OPERATES, parcel,
                "https://use-land-property-data.service.gov.uk",
                reliability=Reliability.AUTHORITATIVE, correlation_group=group,
                observed_at=_iso(date), raw={"price_paid": price},
            ))
            if country:
                claims.append(self.claim(
                    ident, Predicate.INCORPORATED_IN, country,
                    "https://use-land-property-data.service.gov.uk",
                    reliability=Reliability.AUTHORITATIVE, correlation_group=group,
                ))
        return claims


def _iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None
