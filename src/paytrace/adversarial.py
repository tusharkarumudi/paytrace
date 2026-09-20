"""Planted-identifier detection.

The gap nobody in OSINT tooling accounts for: **high-selectivity identifiers are
also high-forgeability identifiers.**

The scoring model treats a shared AdSense publisher ID as worth roughly fourteen
nats precisely because so few sites carry it. But putting a competitor's
``ca-pub-`` string into your page source costs nothing and requires no access to
their account. An adversary who wants a rival attributed to their scraper
network simply plants the rival's ID across it. Every selectivity-based
attribution system — including this one, unguarded — then hands them the result.

This is not hypothetical. Referrer spam, GA property poisoning and AdSense-ID
squatting are established nuisance techniques; using them to manufacture
attribution is a small step from there, and the target of an investigation has
strong motive.

Four checks, in rough order of discriminating power. None is conclusive alone;
together they distinguish an account genuinely operating a site from a string
someone pasted into it.

1. **Reciprocity** — does the other side assert the relationship back?
2. **Load-bearing** — is the identifier functionally live, or inert text?
3. **Temporal depth** — does it have history, or did it appear all at once?
4. **Placement** — is it where a working integration puts it?

Findings demote rather than delete. An identifier that fails these checks is
still evidence — of something, possibly of an attempt to frame someone — and
deleting it hides that.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum

from attribution_graph import Claim, Identifier

from .net import Fetcher


def _strip_www(host: str) -> str:
    """Remove a leading 'www.' label.

    Not `lstrip("www.")` -- that strips any leading run of {w, .}, turning
    "web.example.com" into "eb.example.com" and silently breaking reciprocity
    comparison for every host beginning with those characters.
    """
    return host[4:] if host.startswith("www.") else host


class Verdict(StrEnum):
    CORROBORATED = "corroborated"      # passes reciprocity or load-bearing
    UNVERIFIED = "unverified"          # present, nothing confirms or denies
    SUSPECT = "suspect"                # positive indicators of planting
    INERT = "inert"                    # present but demonstrably non-functional


@dataclass
class Assessment:
    identifier: str
    verdict: Verdict
    checks: dict[str, str] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    @property
    def should_demote(self) -> bool:
        return self.verdict in (Verdict.SUSPECT, Verdict.INERT)


# --------------------------------------------------------------------------- #
# 1. Reciprocity
# --------------------------------------------------------------------------- #

async def check_reciprocity(
    fetcher: Fetcher, domain: str, adsystem: str, seller_id: str
) -> tuple[bool | None, str]:
    """Does ``sellers.json`` name this domain back?

    The strongest single check available in the ad-tech chain, because it
    requires control of *both* sides. A site can declare any seller ID it likes
    in ads.txt; only the actual account holder appears in the exchange's
    sellers.json with a matching domain.

    Returns ``(True, why)`` confirmed, ``(False, why)`` contradicted,
    ``(None, why)`` when the record is confidential or absent.
    """
    data = await fetcher.get_json(f"https://{adsystem}/sellers.json")
    if not data:
        return None, "sellers.json unavailable"
    for s in data.get("sellers", []):
        if str(s.get("seller_id", "")).lower() != seller_id.lower():
            continue
        if int(s.get("is_confidential", 0) or 0):
            return None, "seller record is confidential; reciprocity unverifiable"
        declared = _strip_www((s.get("domain") or "").lower())
        target = _strip_www(domain.lower())
        if not declared:
            return None, "seller record declares no domain"
        if declared == target or target.endswith("." + declared):
            return True, f"sellers.json names {declared}"
        return False, (
            f"sellers.json names {declared}, not {target} — the ads.txt "
            f"declaration is unreciprocated"
        )
    return None, "seller_id absent from sellers.json"


# --------------------------------------------------------------------------- #
# 2. Load-bearing
# --------------------------------------------------------------------------- #

#: A planted ID is text. A real one is wired into a working integration.
_LIVE_CONTEXT = {
    "adsense": (
        re.compile(r"adsbygoogle\.js\?client=ca-pub-", re.I),
        "AdSense loader script carries the publisher ID",
    ),
    "ga4": (
        re.compile(r"googletagmanager\.com/gtag/js\?id=G-", re.I),
        "gtag loader requests the measurement ID",
    ),
    "gtm": (
        re.compile(r"googletagmanager\.com/gtm\.js\?id=GTM-", re.I),
        "GTM container is actually loaded",
    ),
    "fb_pixel": (
        re.compile(r"connect\.facebook\.net/[\w_]+/fbevents\.js", re.I),
        "Pixel base code present",
    ),
    "sentry": (
        re.compile(r"(browser\.sentry-cdn\.com|@sentry/browser|Sentry\.init)", re.I),
        "Sentry SDK initialised",
    ),
}

#: Where planted identifiers tend to end up: comments, meta tags, dead files.
_DEAD_CONTEXT = re.compile(
    r"<!--[^>]{0,400}(ca-pub-\d{16}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{5,9})",
    re.I | re.S,
)


async def check_load_bearing(
    fetcher: Fetcher, domain: str, scheme: str, value: str, html: str | None = None
) -> tuple[bool | None, str]:
    """Is the identifier functionally live, or inert text on the page?"""
    if html is None:
        r = await fetcher.get(f"https://{domain}/", allow_html=True)
        if not r or r.status != 200:
            return None, "page unavailable"
        html = r.text

    if _DEAD_CONTEXT.search(html):
        return False, "identifier appears inside an HTML comment, not live markup"

    pat = _LIVE_CONTEXT.get(scheme)
    if not pat:
        return None, f"no load-bearing test defined for scheme '{scheme}'"
    regex, why = pat
    if regex.search(html):
        return True, why
    return False, (
        f"{scheme} identifier present but the corresponding loader is absent — "
        "the string is on the page without a working integration"
    )


async def check_gtm_container_resolves(
    fetcher: Fetcher, container_id: str
) -> tuple[bool | None, str]:
    """A GTM container that does not resolve was never a real integration."""
    if not re.fullmatch(r"GTM-[A-Z0-9]{5,9}", container_id):
        return None, "not a GTM container id"
    r = await fetcher.get(f"https://www.googletagmanager.com/gtm.js?id={container_id}")
    if not r:
        return None, "container fetch failed"
    if r.status != 200 or len(r.text) < 500:
        return False, "container does not resolve"
    return True, "container resolves and returns a payload"


# --------------------------------------------------------------------------- #
# 3. Temporal depth
# --------------------------------------------------------------------------- #

async def check_temporal_depth(
    fetcher: Fetcher, domain: str, value: str, min_span_days: int = 90
) -> tuple[bool | None, str]:
    """Does the identifier have archived history on this domain?

    A genuine integration accumulates snapshots over months or years. A planted
    string appears at one point with nothing behind it. Absence of history is
    not proof — young domains have none either — which is why this contributes
    to a verdict rather than deciding one.
    """
    cdx = (f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json"
           f"&fl=timestamp,original&filter=statuscode:200&collapse=timestamp:6&limit=60")
    rows = await fetcher.get_json(cdx)
    if not isinstance(rows, list) or len(rows) < 2:
        return None, "no archived snapshots for this domain"

    data = sorted(rows[1:], key=lambda r: r[0])
    picks = [data[0], data[len(data) // 2], data[-1]]
    seen: list[datetime] = []
    for ts, original in {tuple(p) for p in picks}:
        r = await fetcher.get(f"https://web.archive.org/web/{ts}id_/{original}",
                              allow_html=True)
        if r and r.status == 200 and value in r.text:
            with contextlib.suppress(ValueError):
                seen.append(datetime.strptime(ts[:14], "%Y%m%d%H%M%S")
                            .replace(tzinfo=timezone.utc))

    if not seen:
        return False, "identifier absent from every sampled archived snapshot"
    if len(seen) == 1:
        return None, f"identifier seen in one snapshot only ({seen[0]:%Y-%m})"
    span = (max(seen) - min(seen)).days
    if span >= min_span_days:
        return True, (f"identifier present across {span} days of archived history "
                      f"({min(seen):%Y-%m} to {max(seen):%Y-%m})")
    return None, f"archived history spans only {span} days"


# --------------------------------------------------------------------------- #
# 4. Asymmetry
# --------------------------------------------------------------------------- #

def check_asymmetry(
    subject_domain: str,
    identifier_owner_domains: Sequence[str],
    holder_counts: dict[str, int],
) -> tuple[bool | None, str]:
    """Directional test over a shared-identifier cluster.

    If A carries B's identifier but B does not carry A's, and B has far deeper
    presence, the plausible reading is that A copied B — deliberately or by
    lifting B's page template. Either way A is not evidence of common control
    with B, and treating it as such is exactly the error an adversary wants.
    """
    if subject_domain in identifier_owner_domains and len(identifier_owner_domains) > 1:
        others = [d for d in identifier_owner_domains if d != subject_domain]
        subj = holder_counts.get(subject_domain, 0)
        deepest = max((holder_counts.get(d, 0) for d in others), default=0)
        if deepest > subj * 10 and deepest > 20:
            return False, (
                f"{subject_domain} shares this identifier with a substantially "
                f"more established property; template reuse or planting is more "
                f"likely than common control"
            )
    return None, "no asymmetry signal"


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

async def assess_identifier(
    fetcher: Fetcher,
    domain: str,
    scheme: str,
    value: str,
    *,
    html: str | None = None,
    adsystem: str | None = None,
    seller_id: str | None = None,
) -> Assessment:
    """Run every applicable check and reach a verdict."""
    a = Assessment(identifier=f"{scheme}:{value}", verdict=Verdict.UNVERIFIED)

    if adsystem and seller_id:
        ok, why = await check_reciprocity(fetcher, domain, adsystem, seller_id)
        a.checks["reciprocity"] = why
        if ok is True:
            a.verdict = Verdict.CORROBORATED
            a.reasons.append(why)
            return a
        if ok is False:
            a.verdict = Verdict.SUSPECT
            a.reasons.append(why)

    ok, why = await check_load_bearing(fetcher, domain, scheme, value, html)
    a.checks["load_bearing"] = why
    if ok is False:
        a.verdict = Verdict.INERT
        a.reasons.append(why)
    elif ok is True and a.verdict is Verdict.UNVERIFIED:
        a.verdict = Verdict.CORROBORATED
        a.reasons.append(why)

    if scheme == "gtm":
        ok, why = await check_gtm_container_resolves(fetcher, value)
        a.checks["container_resolves"] = why
        if ok is False:
            a.verdict = Verdict.INERT
            a.reasons.append(why)

    ok, why = await check_temporal_depth(fetcher, domain, value)
    a.checks["temporal_depth"] = why
    if ok is False and a.verdict is not Verdict.CORROBORATED:
        a.verdict = Verdict.SUSPECT
        a.reasons.append(why)
    elif ok is True and a.verdict is Verdict.UNVERIFIED:
        a.verdict = Verdict.CORROBORATED
        a.reasons.append(why)

    return a


def apply_assessments(
    claims: Iterable[Claim], assessments: dict[str, Assessment]
) -> list[Claim]:
    """Demote claims resting on identifiers that failed verification.

    Demote, never drop. An inert or unreciprocated identifier is still a fact
    about the page, and if someone is manufacturing attribution then that fact
    is the most interesting thing in the case.
    """
    out: list[Claim] = []
    for c in claims:
        key = c.object.value if isinstance(c.object, Identifier) else None
        a = assessments.get(key or "")
        if a and a.should_demote:
            c.weight = 0.0
            c.raw["demoted"] = f"planted-identifier check: {a.verdict.value}"
            c.raw["adversarial_checks"] = a.checks
        elif a:
            c.raw["adversarial_checks"] = a.checks
        out.append(c)
    return out
