"""Third-party lookup services and specialist registries.

## Why these are scored below the corpus index

Every collector here queries a service that asserts a result without exposing
its method. A reverse-AdSense service says four domains share a publisher ID;
you cannot see when it crawled, how much of the web it covers, or whether it
deduplicates. That is a different epistemic object from
``paytrace-index``, where the holder count is a query against a corpus you
built and can audit.

So a third-party reverse lookup enters at ``MODERATE`` and a corpus lookup at
``AUTHORITATIVE``, and where both are available the corpus wins. The service is
still worth querying — it covers domains your crawl missed, and on day one you
have no corpus at all — but its coverage is unmeasured, which means an absence
from it is not a finding.

## Coverage is not accuracy

These services report presence well and absence badly. "DNSlytics shows no other
domains" means the service has no record, which for a small operator is the
common case regardless of the truth. Absences from them are recorded as
``NOT_COVERED``, never as ``CONFIRMED_ABSENT``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable

from attribution_graph import (
    AbsenceKind,
    Claim,
    Identifier,
    IdKind,
    Predicate,
    Reliability,
    SourceClass,
    absence_claim,
)

from .base import Collector, register

# --------------------------------------------------------------------------- #
# Reverse publisher ID — the core mechanic, without a corpus
# --------------------------------------------------------------------------- #

@register
class ReversePublisherId(Collector):
    """Publisher/analytics ID to the domains that carry it, via third parties.

    This is `paytrace`'s central pivot, and until now it required a corpus index
    you had built yourself. Several public services perform the same lookup, so
    an investigation with no corpus is no longer blind — it is merely relying on
    someone else's crawl.

    Scored below the corpus index deliberately. These services do not publish
    their coverage, so a low holder count from one of them may mean the
    identifier is selective, or may mean the service has not crawled much.
    """

    name = "reverse_publisher_id"
    source_class = SourceClass.OPEN_DATASET
    accepts = (IdKind.ANALYTICS_ID, IdKind.SERVICE_ID)
    priority = 3

    #: Services keyed by the identifier schemes they index.
    SERVICES = {
        "dnslytics": {
            "url": "https://dnslytics.com/reverse-adsense/{value}",
            "schemes": ("adsense", "ga4", "ua", "gtm"),
            "note": "free tier truncates results",
        },
        "spyonweb": {
            "url": "https://spyonweb.com/{value}",
            "schemes": ("adsense", "ua", "ga4"),
            "note": "historical index; coverage skews to older observations",
        },
    }

    _DOMAIN = re.compile(
        r"\b([a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9][a-z0-9\-]{0,62})+)\b", re.I)
    #: Hosts that appear on every such page and are never results.
    _CHROME = frozenset({
        "dnslytics.com", "spyonweb.com", "google.com", "googletagmanager.com",
        "gstatic.com", "cloudflare.com", "twitter.com", "facebook.com",
        "w3.org", "schema.org", "jquery.com", "bootstrapcdn.com",
    })

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        scheme, _, value = ident.value.partition(":")
        if not value:
            return []

        # A service ID (Disqus shortname, Crisp/Intercom app id) is reverse-
        # searchable via source-code indexes rather than reverse-DNS services.
        # Without a configured code-search endpoint this is a documented manual
        # step, recorded so the lead is not silently dropped.
        if ident.kind is IdKind.SERVICE_ID:
            return [absence_claim(
                ident, self.name, AbsenceKind.NOT_CHECKED,
                query_url=f"https://publicwww.com/websites/%22{value}%22/",
                what_was_sought="other domains embedding this service ID",
                note="service-ID reverse lookup needs a source-code search "
                     "index (PublicWWW/Nerdydata); search the query URL "
                     "manually or configure an endpoint")]

        claims: list[Claim] = []
        any_result = False

        for service, cfg in self.SERVICES.items():
            if scheme not in cfg["schemes"]:
                continue
            url = cfg["url"].format(value=value)
            r = await self.fetcher.get(url, allow_html=True)
            if not r or r.status != 200 or not r.text:
                continue

            found = {
                d.lower() for d in self._DOMAIN.findall(re.sub(r"<[^>]+>", " ", r.text))
                if d.lower() not in self._CHROME and d.count(".") <= 3
            }
            if not found:
                continue
            any_result = True

            # One query against one index is one observation, however many
            # domains come back.
            group = f"reverse_lookup|{service}|{ident.value}"
            for domain in sorted(found)[:200]:
                claims.append(self.claim(
                    ident, Predicate.SHARES_ANALYTICS_ID,
                    Identifier(IdKind.DOMAIN, domain), url,
                    reliability=Reliability.MODERATE, correlation_group=group,
                    raw={"service": service, "note": cfg["note"],
                         "coverage": "unpublished — presence is informative, "
                                     "absence is not"}))

        if not any_result:
            claims.append(absence_claim(
                ident, "reverse_publisher_id", AbsenceKind.EXPECTED_ABSENT,
                query_url="https://dnslytics.com/reverse-adsense/",
                what_was_sought="other domains carrying this publisher ID",
                note="third-party reverse lookups do not publish coverage; "
                     "no result does not mean no other domains"))
        return claims


# --------------------------------------------------------------------------- #
# ICIJ Offshore Leaks
# --------------------------------------------------------------------------- #

@register
class OffshoreLeaks(Collector):
    """ICIJ Offshore Leaks database.

    Entities, officers and intermediaries from the Panama, Paradise, Pandora and
    Bahamas leaks. Journalism-grade and publicly searchable, and the only route
    in this toolkit to a beneficial owner behind a secrecy-jurisdiction shell.

    Two cautions the collector encodes. The data is a **leak snapshot**, not a
    live register, so a record reflects the position at disclosure and may be
    years stale. And ICIJ states plainly that appearing in it is not evidence of
    wrongdoing — a report that implies otherwise is defamatory, so the claim
    carries that qualifier into the graph.
    """

    name = "icij_offshore_leaks"
    source_class = SourceClass.PUBLIC_REGISTRY
    accepts = (IdKind.ORG_NAME, IdKind.PERSON_NAME)
    priority = 3

    SEARCH = "https://offshoreleaks.icij.org/search?q={q}&e=&c=&j=&d="
    API = "https://offshoreleaks.icij.org/api/v1/search?q={q}"

    QUALIFIER = ("Presence in the ICIJ Offshore Leaks database is not evidence "
                 "of wrongdoing. Offshore entities have lawful uses.")

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        from attribution_graph import lookup_variants

        claims: list[Claim] = []
        seen: set[str] = set()

        for variant in lookup_variants(ident.value, 4):
            url = self.API.format(q=variant.replace(" ", "%20"))
            data = await self.fetcher.get_json(url)
            if not data:
                continue

            for rec in (data if isinstance(data, list)
                        else data.get("results", []))[:10]:
                node_id = str(rec.get("node_id") or rec.get("id") or "")
                if not node_id or node_id in seen:
                    continue
                seen.add(node_id)

                group = f"icij|{node_id}"
                page = f"https://offshoreleaks.icij.org/nodes/{node_id}"

                if rec.get("name"):
                    claims.append(self.claim(
                        ident, Predicate.SAME_AS,
                        Identifier(IdKind.ORG_NAME, rec["name"]), page,
                        reliability=Reliability.MODERATE,
                        correlation_group=group,
                        raw={"source_leak": rec.get("sourceID"),
                             "node_type": rec.get("type"),
                             "matched_variant": variant,
                             "qualifier": self.QUALIFIER,
                             "snapshot": "leak disclosure, not a live register"}))
                if rec.get("jurisdiction"):
                    claims.append(self.claim(
                        ident, Predicate.REGISTERED_ADDRESS,
                        Identifier(IdKind.POSTAL_ADDRESS,
                                   f"jurisdiction: {rec['jurisdiction']}"), page,
                        reliability=Reliability.WEAK,
                        correlation_group=group,
                        raw={"field": "jurisdiction",
                             "qualifier": self.QUALIFIER}))
                if rec.get("address"):
                    claims.append(self.claim(
                        ident, Predicate.REGISTERED_ADDRESS,
                        Identifier(IdKind.POSTAL_ADDRESS, rec["address"]), page,
                        reliability=Reliability.MODERATE,
                        correlation_group=group,
                        raw={"qualifier": self.QUALIFIER}))

        if not claims:
            claims.append(absence_claim(
                ident, self.name, AbsenceKind.CHECKED_ABSENT,
                query_url=self.SEARCH.format(q=ident.value),
                what_was_sought="offshore entity, officer or intermediary record"))
        return claims


# --------------------------------------------------------------------------- #
# China
# --------------------------------------------------------------------------- #

@register
class CninfoDisclosure(Collector):
    """CNINFO — mandated disclosure for Shanghai and Shenzhen listed companies.

    The authoritative filing venue for Chinese listed entities: annual reports,
    shareholder structure, related-party transactions. The analogue of EDGAR,
    and the right first stop when a chain reaches a Chinese company.

    Coverage is limited to *listed* companies. The overwhelming majority of
    Chinese entities are unlisted and appear only in provincial AMR registries,
    which are not openly queryable — so an absence here says very little.
    """

    name = "cninfo_disclosure"
    source_class = SourceClass.PUBLIC_REGISTRY
    accepts = (IdKind.ORG_NAME,)
    priority = 4

    SEARCH = "https://www.cninfo.com.cn/new/fulltextSearch?notautosubmit=&keyWord={q}"
    API = "https://www.cninfo.com.cn/new/information/topSearch/query"

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        r = await self.fetcher.post_form(
            self.API, {"keyWord": ident.value, "maxNum": "10"}) \
            if hasattr(self.fetcher, "post_form") else None
        if not r:
            return [absence_claim(
                ident, self.name, AbsenceKind.NOT_CHECKED,
                query_url=self.SEARCH.format(q=ident.value),
                what_was_sought="Chinese listed-company disclosure",
                note="CNINFO requires a form POST; search manually at the URL")]

        claims: list[Claim] = []
        try:
            records = json.loads(r) if isinstance(r, str) else r
        except json.JSONDecodeError:
            return []

        for rec in (records or [])[:10]:
            code = rec.get("code")
            name = rec.get("zwjc") or rec.get("orgId")
            if not code:
                continue
            group = f"cninfo|{code}"
            page = f"https://www.cninfo.com.cn/new/disclosure/stock?stockCode={code}"
            claims.append(self.claim(
                ident, Predicate.SAME_AS,
                Identifier(IdKind.COMPANY_NUMBER, f"cn/{code}"), page,
                reliability=Reliability.AUTHORITATIVE, correlation_group=group,
                raw={"listed_name": name,
                     "coverage": "listed companies only; unlisted entities "
                                 "appear only in provincial AMR registries"}))
        return claims


# --------------------------------------------------------------------------- #
# Business directories
# --------------------------------------------------------------------------- #

@register
class BusinessDirectory(Collector):
    """Infobel and Manta — commercial business directories.

    Useful for an address or a phone number attached to a trading name, and for
    little else. These are compiled from self-submission and purchased lists, so
    an entry proves someone submitted it rather than that a company exists, and
    stale records persist for years.

    Everything from here is corroborative: it can support a link established by
    a registry, and cannot establish one.
    """

    name = "business_directory"
    source_class = SourceClass.OPEN_DATASET
    accepts = (IdKind.ORG_NAME,)
    priority = 5

    SOURCES = {
        "infobel": "https://www.infobel.com/en/world/search?name={q}",
        "manta": "https://www.manta.com/search?search={q}",
    }

    _PHONE = re.compile(r"\+?[\d][\d\s().\-]{7,20}\d")
    _POSTAL = re.compile(r"\d{1,6}[\w\s.,\-]{5,90}?\b[A-Z]{2}\b\s*\d{4,6}")

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        claims: list[Claim] = []
        for source, template in self.SOURCES.items():
            url = template.format(q=ident.value.replace(" ", "+"))
            r = await self.fetcher.get(url, allow_html=True)
            if not r or r.status != 200 or not r.text:
                continue

            text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", r.text))
            if ident.value.lower() not in text.lower():
                continue

            group = f"directory|{source}|{ident.value}"
            for m in list(dict.fromkeys(self._POSTAL.findall(text)))[:2]:
                claims.append(self.claim(
                    ident, Predicate.REGISTERED_ADDRESS,
                    Identifier(IdKind.POSTAL_ADDRESS, m.strip()), url,
                    reliability=Reliability.WEAK, correlation_group=group,
                    raw={"source": source,
                         "caveat": "self-submitted directory listing; "
                                   "corroborative only"}))
            for m in list(dict.fromkeys(self._PHONE.findall(text)))[:2]:
                claims.append(self.claim(
                    ident, Predicate.PROFILE_BINDING,
                    Identifier(IdKind.PHONE, re.sub(r"[^\d+]", "", m)), url,
                    reliability=Reliability.WEAK, correlation_group=group,
                    raw={"source": source, "caveat": "self-submitted listing"}))
        return claims


# --------------------------------------------------------------------------- #
# Blockchain
# --------------------------------------------------------------------------- #

@register
class ChainActivity(Collector):
    """Wallet activity via public block explorers.

    Establishes that an address exists, when it was active, and what it
    transacted with. It does **not** establish who controls it, and the
    collector will not imply otherwise: a wallet links to a person only through
    an off-chain disclosure — an exchange KYC record, a published donation
    address, a signed message.

    So on-chain data enters as activity evidence attached to the address, never
    as an identity claim. `blockexplorer.com` is defunct; these are the
    maintained endpoints.
    """

    name = "chain_activity"
    source_class = SourceClass.PUBLIC_REGISTRY
    accepts = (IdKind.URL,)
    priority = 4

    EXPLORERS = {
        "btc": "https://mempool.space/api/address/{addr}",
        "eth": "https://api.blockchair.com/ethereum/dashboards/address/{addr}",
        "xmr": None,   # Monero is private by design; there is nothing to query.
    }

    _PREFIX = re.compile(r"^(btc|eth|xmr):(.+)$", re.I)

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        m = self._PREFIX.match(ident.value)
        if not m:
            return []
        chain, addr = m.group(1).lower(), m.group(2)

        if chain == "xmr":
            return [absence_claim(
                ident, self.name, AbsenceKind.EXPECTED_ABSENT,
                query_url="", what_was_sought="on-chain activity",
                note="Monero conceals amounts, senders and recipients by "
                     "design; there is no public ledger to query")]

        template = self.EXPLORERS.get(chain)
        if not template:
            return []
        url = template.format(addr=addr)
        data = await self.fetcher.get_json(url)
        if not data:
            return []

        group = f"chain|{chain}|{addr}"
        stats = (data.get("chain_stats") or data.get("data", {}).get(addr, {})
                 or {})
        tx_count = (stats.get("tx_count")
                    or (stats.get("address") or {}).get("transaction_count"))

        claims = [self.claim(
            ident, Predicate.PROFILE_BINDING,
            Identifier(IdKind.URL, f"chain:{chain}/{addr}"), url,
            reliability=Reliability.AUTHORITATIVE, correlation_group=group,
            raw={"transactions": tx_count,
                 "limitation": "on-chain activity establishes that an address "
                               "exists and transacted; it does not establish "
                               "who controls it"})]
        return claims


# --------------------------------------------------------------------------- #
# Sources catalogued but deliberately not automated
# --------------------------------------------------------------------------- #

#: Reasons kept in code so the decision travels with the tool.
NOT_AUTOMATED = {
    "blackbookonline.info": (
        "Directory of US public-record sources, oriented to people search. "
        "Consistent with the data-broker policy: an investigator may use it "
        "manually, but assembling person-keyed lookups behind one command is "
        "the artifact this toolkit declines to build. Person-scoped and manual."),
    "openlinkprofiler.org": (
        "Backlink analysis. Genuinely additive for portfolio discovery — a "
        "network often interlinks — but the service has been intermittently "
        "unavailable and publishes no coverage figures. Catalogued for manual "
        "use rather than depended on."),
    "dnsdumpster.com": (
        "Subdomain and DNS reconnaissance, largely overlapping crt.sh and "
        "mnemonic passive DNS, both of which are already collectors with "
        "better-understood coverage. Adds little beyond them."),
    "wipo.int/pct-contracting-states": (
        "A list of treaty member states, not a searchable registry. WIPO's "
        "Global Brand Database is the searchable resource and is catalogued "
        "separately."),
    "blockexplorer.com": (
        "Defunct. mempool.space and blockchair are the maintained endpoints "
        "and are used by chain_activity."),
}
