"""Portfolio expansion: from one seeded domain to an actor's full estate.

The chain this implements:

    seed domain
      -> analytics IDs (live) + analytics IDs (Wayback, historical)
      -> reverse index: every domain sharing those IDs
      -> ads.txt seller IDs (live + historical)
      -> reverse index: every domain declaring those seller IDs
      -> sellers.json: the legal entity paid for each
      -> RDAP now + archived registrant data then
      -> scored, deduplicated, and handed to attribution-graph

Two properties make this work better than it has any right to.

**Historical IDs still link present domains.** An operator who consolidated
AdSense accounts in 2021 leaves the 2019 shared ID in the archive, and that
observation is valid evidence that the domains were commonly controlled -- with
its weight correctly decayed by the age of the observation rather than being
either discarded or treated as current.

**Reverse expansion needs the selectivity brake or it explodes.** A GTM
container ID on four sites is a portfolio. A Google Tag Manager ID present on
forty thousand sites is a template. The same pivot produces both, and the only
thing distinguishing them is the holder count, which is why expansion is gated
on measured selectivity rather than a hop limit.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone

from attribution_graph import (
    Claim,
    Identifier,
    IdKind,
    Predicate,
    Reliability,
    selectivity,
)

from .adstxt import BOILERPLATE_THRESHOLD
from .collectors.analytics import extract_ids
from .index import AdsTxtIndex
from .net import Fetcher

#: An identifier held by more than this many domains is a platform artifact,
#: not a portfolio signal. Expansion stops; the edge is still recorded, demoted.
MAX_PORTFOLIO_HOLDERS = 150

#: Expansion halts here regardless of selectivity. A "portfolio" of ten thousand
#: domains means a pivot went wrong, and continuing wastes the request budget.
MAX_PORTFOLIO = 500


@dataclass
class PortfolioResult:
    seed: str
    domains: dict[str, list[str]] = field(default_factory=dict)   # domain -> reasons
    identifiers: dict[str, int] = field(default_factory=dict)     # id key -> holders
    rejected: list[tuple[str, str]] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"portfolio for {self.seed}: {len(self.domains)} domains", ""]
        for d, reasons in sorted(self.domains.items()):
            lines.append(f"  {d}")
            for r in reasons[:4]:
                lines.append(f"      via {r}")
        if self.rejected:
            lines += ["", "pivots rejected as non-discriminating:"]
            for ident, why in self.rejected[:20]:
                lines.append(f"  {ident} — {why}")
        return "\n".join(lines)


class PortfolioExpander:
    """Reverse-pivot engine over the corpus index."""

    def __init__(self, index: AdsTxtIndex, fetcher: Fetcher, use_wayback: bool = True) -> None:
        self.index = index
        self.fetcher = fetcher
        self.use_wayback = use_wayback

    # ---- identifier discovery --------------------------------------------- #

    async def _ids_for_domain(self, domain: str) -> list[tuple[str, str, Reliability, datetime | None]]:  # noqa: E501
        """Live plus historical publisher IDs for one domain."""
        found: list[tuple[str, str, Reliability, datetime | None]] = []

        r = await self.fetcher.get(f"https://{domain}/", allow_html=True)
        if r and r.status == 200:
            for scheme, val, rel in extract_ids(r.text):
                found.append((scheme, val, rel, None))

        if self.use_wayback:
            cdx = (f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json"
                   f"&fl=timestamp,original&filter=statuscode:200"
                   f"&collapse=timestamp:4&limit=100")
            rows = await self.fetcher.get_json(cdx)
            if isinstance(rows, list) and len(rows) > 1:
                data = sorted(rows[1:], key=lambda x: x[0])
                # Oldest, midpoint, and most recent. The oldest matters most:
                # it predates the operator's attribution hygiene.
                picks = [data[0], data[len(data) // 2], data[-1]]
                for ts, original in {tuple(p) for p in picks}:
                    snap = f"https://web.archive.org/web/{ts}id_/{original}"
                    rr = await self.fetcher.get(snap, allow_html=True)
                    if not rr or rr.status != 200:
                        continue
                    when = _from_ts(ts)
                    for scheme, val, rel in extract_ids(rr.text):
                        found.append((scheme, val, rel, when))
        return found

    # ---- expansion --------------------------------------------------------- #

    @staticmethod
    def _add_domain(res: PortfolioResult, domain: str, reason: str,
                    max_domains: int) -> bool:
        """The only way a domain enters a portfolio. False once the cap is hit.

        The cap used to be re-implemented at each pivot site, and the
        OWNERDOMAIN pivot was not one of them -- so `expand(seed,
        max_domains=3)` returned 11 domains from a seed with ten
        OWNERDOMAIN-linked sites. OWNERDOMAIN is self-asserted, which makes it
        exactly the surface an operator can inflate at will.
        """
        if domain in res.domains:
            res.domains[domain].append(reason)
            return True
        if len(res.domains) >= max_domains:
            return False
        res.domains[domain] = [reason]
        return True

    async def expand(self, seed: str, max_domains: int = MAX_PORTFOLIO) -> PortfolioResult:
        if max_domains < 1:
            raise ValueError(
                f"max_domains must be at least 1, got {max_domains}. "
                "The seed itself occupies one slot.")

        res = PortfolioResult(seed=seed)
        res.domains[seed] = ["seed"]

        # 1. publisher IDs, live and historical
        ids = await self._ids_for_domain(seed)

        # 2. seller IDs, live and historical
        seller_ids: set[str] = set()
        for adsystem, sid in self.index.sellers_for_domain(seed):
            seller_ids.add(f"{adsystem}/{sid}")

        # 3. reverse-pivot each identifier, gated on selectivity
        for scheme, val, rel, when in ids:
            key = f"{scheme}:{val}"
            holders = self.index.holders_analytics(scheme, val)
            res.identifiers[key] = holders

            if holders > MAX_PORTFOLIO_HOLDERS:
                res.rejected.append((
                    key,
                    f"{holders} holders — platform artifact, not a portfolio "
                    f"(selectivity {selectivity(holders, self.index.universe()):.2e})"
                ))
                continue

            for d in self.index.domains_for_analytics(scheme, val):
                tag = f"{key}{' (archived ' + when.strftime('%Y-%m') + ')' if when else ''}"
                if not self._add_domain(res, d, tag, max_domains):
                    break
                res.claims.append(Claim(
                    subject=Identifier(IdKind.DOMAIN, seed),
                    predicate=Predicate.SHARES_ANALYTICS_ID,
                    object=Identifier(IdKind.DOMAIN, d),
                    collector="portfolio_expander",
                    source_url=f"index://analytics/{key}",
                    reliability=rel,
                    observed_at=when,
                    # All domains sharing one ID are one observation of one
                    # account, not N independent observations.
                    correlation_group=f"portfolio|{key}",
                    raw={"shared_identifier": key, "holders": holders,
                         "historical": when is not None},
                ))

        for sid in seller_ids:
            adsystem, s = sid.split("/", 1)
            holders = len(self.index.sites_for_seller(adsystem, s))
            res.identifiers[f"seller_id:{sid}"] = holders

            # A DIRECT label is not a relationship. Networks hand publishers a
            # block to paste, so the same account appears on tens of thousands
            # of unrelated domains -- expanding on one manufactures a portfolio
            # out of a template.
            if holders > BOILERPLATE_THRESHOLD:
                res.rejected.append((
                    f"seller_id:{sid}",
                    f"{holders} holders — pasted network template line, not a "
                    f"declared relationship, whatever its DIRECT/RESELLER label"))
                continue
            if holders > MAX_PORTFOLIO_HOLDERS:
                res.rejected.append((f"seller_id:{sid}",
                                     f"{holders} holders — network-level seller, not an operator"))
                continue
            for d in self.index.sites_for_seller(adsystem, s):
                if not self._add_domain(res, d, f"seller_id:{sid}", max_domains):
                    break
                res.claims.append(Claim(
                    subject=Identifier(IdKind.DOMAIN, seed),
                    predicate=Predicate.SELLER_OF,
                    object=Identifier(IdKind.DOMAIN, d),
                    collector="portfolio_expander",
                    source_url=f"index://seller/{sid}",
                    reliability=Reliability.STRONG,
                    correlation_group=f"portfolio|seller:{sid}",
                    raw={"shared_identifier": sid, "holders": holders},
                ))

        # 4. OWNERDOMAIN — self-published, so no selectivity gate applies, but
        # the size cap still does. Self-assertion is the one pivot an operator
        # controls outright, so exempting it from the cap made the cheapest
        # surface to inflate the only uncapped one.
        for owner in self.index.owner_domains_for(seed):
            capped = False
            for d in self.index.sites_for_owner(owner):
                if not self._add_domain(res, d, f"OWNERDOMAIN={owner}",
                                        max_domains):
                    capped = True
                    break
            if capped:
                res.rejected.append((
                    f"OWNERDOMAIN={owner}",
                    f"portfolio cap of {max_domains} reached; further "
                    "self-asserted domains not expanded"))
                break

        return res

    # ---- registrant reconstruction ----------------------------------------- #

    async def registrant_history(self, domains: list[str]) -> list[Claim]:
        """Current RDAP plus archived pre-redaction registrant data.

        GDPR-era WHOIS redaction began in 2018. For any domain registered before
        then, the archive frequently holds a registrant name and email the live
        record no longer shows -- and that older record is often the only
        non-proxied identity in the whole portfolio.
        """
        claims: list[Claim] = []
        sem = asyncio.Semaphore(5)

        async def one(domain: str) -> None:
            async with sem:
                d = Identifier(IdKind.DOMAIN, domain)

                data = await self.fetcher.get_json(f"https://rdap.org/domain/{domain}")
                if data:
                    for ent in data.get("entities", []) or []:
                        roles = [r.lower() for r in (ent.get("roles") or [])]
                        if "registrant" not in roles:
                            continue
                        for item in ((ent.get("vcardArray") or [None, []])[1] or []):
                            if (isinstance(item, list) and len(item) >= 4
                                    and item[0].lower() in ("fn", "email", "org")
                                    and isinstance(item[3], str)):
                                val = item[3].strip()
                                if _redacted(val):
                                    continue
                                kind = (IdKind.EMAIL if item[0].lower() == "email"
                                        else IdKind.ORG_NAME)
                                claims.append(Claim(
                                    subject=d, predicate=Predicate.REGISTRANT,
                                    object=Identifier(kind, val),
                                    collector="rdap_current",
                                    source_url=f"https://rdap.org/domain/{domain}",
                                    reliability=Reliability.MODERATE,
                                    correlation_group=f"rdap|{domain}",
                                ))

                cdx = (f"https://web.archive.org/cdx/search/cdx?url={domain}/*"
                       f"&output=json&fl=timestamp,original&filter=statuscode:200"
                       f"&collapse=urlkey&limit=40&from=2010&to=2018")
                rows = await self.fetcher.get_json(cdx)
                if not isinstance(rows, list) or len(rows) < 2:
                    return
                for ts, original in rows[1:6]:
                    if not any(k in original.lower() for k in
                               ("contact", "about", "impressum", "legal", "privacy")):
                        continue
                    snap = f"https://web.archive.org/web/{ts}id_/{original}"
                    r = await self.fetcher.get(snap, allow_html=True)
                    if not r or r.status != 200:
                        continue
                    from .collectors.analytics import _EMAIL, _is_role_or_platform
                    for em in _EMAIL.findall(r.text)[:5]:
                        if _is_role_or_platform(em):
                            continue
                        claims.append(Claim(
                            subject=d, predicate=Predicate.REGISTRANT,
                            object=Identifier(IdKind.EMAIL, em.lower()),
                            collector="wayback_registrant",
                            source_url=snap,
                            reliability=Reliability.MODERATE,
                            observed_at=_from_ts(ts),
                            correlation_group=f"wayback_contact|{domain}|{ts[:6]}",
                            raw={"pre_redaction": ts[:4] < "2018", "snapshot": ts},
                        ))

        await asyncio.gather(*(one(d) for d in domains[:60]))
        return claims


_REDACTION_TOKENS = (
    "redacted", "privacy", "whoisguard", "withheld", "proxy", "protect",
    "not disclosed", "data protected", "gdpr", "statutory masking",
)


def _redacted(v: str) -> bool:
    low = v.lower()
    return any(t in low for t in _REDACTION_TOKENS)


def _from_ts(ts: str) -> datetime | None:
    try:
        return datetime.strptime(str(ts)[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
