"""Analytics-ID portfolio discovery and historical reconstruction.

Two collectors that work as a pair.

``analytics_ids`` extracts publisher-account identifiers from page source.
These are the highest-selectivity infrastructure identifiers that exist: a GA4
measurement ID or an AdSense publisher ID belongs to one account, and an
operator running thirty sites from one account links all thirty.

``wayback`` reconstructs the same identifiers *historically*. This is the more
valuable of the two, for a reason that is specific to how operators behave:
attribution hygiene improves over time. A network running today behind privacy
proxies, split analytics accounts and clean ads.txt was frequently sloppy in
2019 -- same AdSense ID across the portfolio, a real registrant in WHOIS, a
contact page with a named person. Wayback holds that earlier, sloppier state,
and the ID observed in 2019 is still a valid link to the domain today.

The operator cleaned up. The archive did not.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime, timezone

from attribution_graph import Claim, Identifier, IdKind, Predicate, Reliability, SourceClass

from .base import Collector, register

# --------------------------------------------------------------------------- #
# Publisher-account identifier patterns
# --------------------------------------------------------------------------- #
#
# Ordered by selectivity. Account-level IDs (AdSense, GA4, GTM) bind a portfolio
# to one billing or console account. Property-level IDs are weaker but still far
# above infrastructure.

ID_PATTERNS: dict[str, tuple[re.Pattern, Reliability]] = {
    # ca-pub-XXXXXXXXXXXXXXXX -- one AdSense payee account
    "adsense": (re.compile(r"\bca-pub-(\d{16})\b"), Reliability.AUTHORITATIVE),
    # pub-XXXXXXXXXXXXXXXX in ads.txt context
    "adsense_pub": (re.compile(r"\bpub-(\d{16})\b"), Reliability.AUTHORITATIVE),
    # G-XXXXXXXXXX GA4 measurement
    "ga4": (re.compile(r"\b(G-[A-Z0-9]{8,12})\b"), Reliability.STRONG),
    # UA-XXXXXXXX-N legacy Universal Analytics; the account part is UA-XXXXXXXX
    "ua": (re.compile(r"\b(UA-\d{4,10})-\d{1,4}\b"), Reliability.AUTHORITATIVE),
    # GTM-XXXXXXX container
    "gtm": (re.compile(r"\b(GTM-[A-Z0-9]{5,9})\b"), Reliability.STRONG),
    # AdMob / AdManager network code
    "admanager": (re.compile(r"/(\d{6,12})/[\w\-/]+['\"]?\s*[,)]"), Reliability.MODERATE),
    # Facebook Pixel
    "fb_pixel": (re.compile(r"fbq\(['\"]init['\"],\s*['\"](\d{15,16})['\"]"), Reliability.STRONG),
    # Sentry DSN -- the public key plus project id
    "sentry": (re.compile(r"https://([0-9a-f]{32})@[\w.\-]+/(\d+)"), Reliability.AUTHORITATIVE),
    # Yandex Metrica
    "yandex": (re.compile(r"ym\((\d{6,10}),"), Reliability.STRONG),
    # Microsoft Clarity
    "clarity": (re.compile(r"clarity\.ms/tag/([a-z0-9]{8,12})"), Reliability.STRONG),
    # Hotjar
    "hotjar": (re.compile(r"hjid\s*:\s*(\d{6,9})"), Reliability.STRONG),
    # Amplitude
    "amplitude": (re.compile(r"amplitude[^'\"]*['\"]([0-9a-f]{32})['\"]"), Reliability.STRONG),
    # Cloudflare Web Analytics token
    "cf_beacon": (re.compile(r"beacon\.min\.js['\"][^>]*token['\"]?:\s*['\"]([0-9a-f]{32})"),
                  Reliability.STRONG),
}

#: IDs belonging to platforms rather than operators. Matching these links you to
#: Google, not to a suspect.
ID_DENYLIST = {
    "ca-pub-0000000000000000", "UA-0000000", "G-XXXXXXXXXX",
    "GTM-XXXXXX", "GTM-XXXXXXX",
}


def extract_ids(html: str) -> list[tuple[str, str, Reliability]]:
    """Return (scheme, value, reliability) for every publisher ID in page source."""
    out: list[tuple[str, str, Reliability]] = []
    seen: set[str] = set()
    for scheme, (pat, rel) in ID_PATTERNS.items():
        for m in pat.finditer(html):
            val = m.group(1)
            if not val or val in ID_DENYLIST:
                continue
            key = f"{scheme}:{val}"
            if key in seen or val in seen:
                continue
            # ca-pub-N and pub-N are the same AdSense account seen two ways.
            # Recording both would double-count one observation.
            seen.add(key)
            seen.add(val)
            out.append((scheme, val, rel))
    return out


@register
class AnalyticsIds(Collector):
    """Publisher-account IDs from live page source."""

    name = "analytics_ids"
    source_class = SourceClass.SELF_PUBLISHED
    accepts = (IdKind.DOMAIN,)
    priority = 2

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        claims: list[Claim] = []
        for path in ("", "/", "/index.html"):
            url = f"https://{ident.value}{path}"
            r = await self.fetcher.get(url, allow_html=True)
            if r and r.status == 200 and len(r.text) > 200:
                break
        else:
            return []

        # One correlation group per page fetch: thirty IDs on one page are one
        # observation of one site's configuration, not thirty.
        group = f"analytics|{ident.value}"

        # Extension and app store links are mandated-disclosure pointers: the
        # store displays a publisher identity the operator had to provide.
        # These were previously extracted and discarded.
        from .disclosure import extract_store_identifiers
        for sid in extract_store_identifiers(r.text):
            claims.append(self.claim(
                ident, Predicate.OPERATES, Identifier(IdKind.URL, sid), url,
                reliability=Reliability.STRONG, correlation_group=group,
                raw={"pivot": "mandated store disclosure"},
            ))

        for scheme, val, rel in extract_ids(r.text):
            claims.append(self.claim(
                ident, Predicate.SHARES_ANALYTICS_ID,
                Identifier(IdKind.ANALYTICS_ID, f"{scheme}:{val}"), url,
                reliability=rel, correlation_group=group,
                raw={"scheme": scheme},
            ))
        return claims


# --------------------------------------------------------------------------- #
# Wayback Machine
# --------------------------------------------------------------------------- #

@register
class Wayback(Collector):
    """Historical reconstruction via the Internet Archive CDX API.

    Three things are recovered that the live site no longer exposes:

    1. **Historical analytics IDs.** Operators consolidate or split accounts.
       An AdSense ID shared across a portfolio in 2019 links those domains even
       if each has its own account today.
    2. **Historical ads.txt.** Seller IDs get rotated after enforcement actions.
       The prior seller ID is often still resolvable in sellers.json.
    3. **Pre-redaction registrant data.** GDPR-era WHOIS redaction began in
       2018; archived WHOIS-display pages and site contact pages from before
       then frequently name a real registrant.

    Evidence is stamped with the snapshot timestamp, so the scoring model's
    temporal decay applies correctly -- a 2016 observation is weighted as a 2016
    observation, not as something learned today.
    """

    name = "wayback"
    source_class = SourceClass.OPEN_DATASET
    accepts = (IdKind.DOMAIN,)
    priority = 4

    CDX = "https://web.archive.org/cdx/search/cdx"
    SNAP = "https://web.archive.org/web"

    #: Snapshots to sample per target. Sampled across the timeline rather than
    #: taken consecutively -- consecutive captures are near-identical and would
    #: produce correlated evidence dressed up as independent.
    MAX_SNAPSHOTS = 6

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        claims: list[Claim] = []
        claims.extend(await self._homepage_history(ident))
        claims.extend(await self._ads_txt_history(ident))
        return claims

    async def _cdx(self, url_pattern: str, limit: int = 200) -> list[list[str]]:
        url = (f"{self.CDX}?url={url_pattern}&output=json&fl=timestamp,original,statuscode"
               f"&filter=statuscode:200&collapse=timestamp:6&limit={limit}")
        rows = await self.fetcher.get_json(url)
        if not isinstance(rows, list) or len(rows) < 2:
            return []
        return rows[1:]

    @staticmethod
    def _sample(rows: list[list[str]], n: int) -> list[list[str]]:
        """Spread the sample across the timeline, keeping the oldest.

        The oldest capture matters most: it predates the operator's attribution
        hygiene.
        """
        if len(rows) <= n:
            return rows
        rows = sorted(rows, key=lambda r: r[0])
        step = len(rows) / (n - 1)
        picked = [rows[0]] + [rows[min(int(i * step), len(rows) - 1)] for i in range(1, n)]
        seen, out = set(), []
        for r in picked:
            if r[0] not in seen:
                seen.add(r[0])
                out.append(r)
        return out

    async def _homepage_history(self, ident: Identifier) -> list[Claim]:
        rows = await self._cdx(ident.value)
        claims: list[Claim] = []
        for ts, original, _ in self._sample(rows, self.MAX_SNAPSHOTS):
            snap = f"{self.SNAP}/{ts}id_/{original}"
            r = await self.fetcher.get(snap, allow_html=True)
            if not r or r.status != 200 or len(r.text) < 200:
                continue
            when = _from_ts(ts)
            # One group per snapshot. Consecutive captures of one site are not
            # independent evidence.
            group = f"wayback|{ident.value}|{ts[:6]}"

            for scheme, val, rel in extract_ids(r.text):
                claims.append(self.claim(
                    ident, Predicate.SHARES_ANALYTICS_ID,
                    Identifier(IdKind.ANALYTICS_ID, f"{scheme}:{val}"), snap,
                    reliability=rel, correlation_group=group, observed_at=when,
                    raw={"scheme": scheme, "snapshot": ts, "historical": True},
                ))

            for email in _EMAIL.findall(r.text)[:10]:
                if _is_role_or_platform(email):
                    continue
                claims.append(self.claim(
                    ident, Predicate.REGISTRANT,
                    Identifier(IdKind.EMAIL, email.lower()), snap,
                    reliability=Reliability.MODERATE,
                    correlation_group=group, observed_at=when,
                    raw={"snapshot": ts, "historical": True,
                         "source": "archived page contact"},
                ))
        return claims

    async def _ads_txt_history(self, ident: Identifier) -> list[Claim]:
        rows = await self._cdx(f"{ident.value}/ads.txt", limit=100)
        claims: list[Claim] = []
        for ts, original, _ in self._sample(rows, 4):
            snap = f"{self.SNAP}/{ts}id_/{original}"
            r = await self.fetcher.get(snap, allow_html=True)
            if not r or r.status != 200:
                continue
            when = _from_ts(ts)
            group = f"wayback_ads|{ident.value}|{ts[:6]}"
            for line in r.text.splitlines()[:2000]:
                body = line.split("#", 1)[0].strip()
                parts = [p.strip() for p in body.split(",")]
                if len(parts) >= 3 and "." in parts[0] and parts[2].upper() == "DIRECT":
                    claims.append(self.claim(
                        ident, Predicate.SELLER_OF,
                        Identifier(IdKind.SELLER_ID, f"{parts[0].lower()}/{parts[1]}"),
                        snap, reliability=Reliability.STRONG,
                        correlation_group=group, observed_at=when,
                        raw={"snapshot": ts, "historical": True},
                    ))
        return claims


_EMAIL = re.compile(r"[\w.+\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,4}")

_PLATFORM_DOMAINS = (
    "google.com", "googlemail.com", "gstatic.com", "facebook.com", "w3.org",
    "schema.org", "wordpress.org", "example.com", "sentry.io", "cloudflare.com",
)
_ROLE = {"noreply", "no-reply", "postmaster", "abuse", "hostmaster", "webmaster",
         "donotreply", "privacy", "dpo"}


def _is_role_or_platform(email: str) -> bool:
    local, _, domain = email.lower().partition("@")
    return local in _ROLE or any(domain.endswith(d) for d in _PLATFORM_DOMAINS)


def _from_ts(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
