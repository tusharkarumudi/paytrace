"""Infrastructure collectors -- keyless replacements for the paid APIs in the
existing domain pipeline.

  VirusTotal reverse-DNS  ->  mnemonic passive DNS + InternetDB + RapidDNS
  Censys certificate      ->  crt.sh + tlsx
  Censys favicon index    ->  local mmh3 over a CT-derived host corpus
  Paid WHOIS APIs         ->  RDAP (IANA bootstrap, structured, no scraping)
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime, timezone

from attribution_graph import Claim, Identifier, IdKind, Predicate, Reliability, SourceClass

from .base import Collector, register


@register
class Rdap(Collector):
    """RDAP replaces WHOIS scraping: structured JSON, no rate-limit theatre,
    and redaction is explicit rather than silently blank."""

    name = "rdap"
    source_class = SourceClass.PUBLIC_REGISTRY
    accepts = (IdKind.DOMAIN, IdKind.IP, IdKind.ASN)
    priority = 2

    REDACTION = re.compile(
        r"redacted|privacy|whoisguard|withheld|proxy|protect|not disclosed|data protected",
        re.I,
    )

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        kind = {IdKind.DOMAIN: "domain", IdKind.IP: "ip", IdKind.ASN: "autnum"}[ident.kind]
        val = ident.value.lstrip("AS") if ident.kind is IdKind.ASN else ident.value
        url = f"https://rdap.org/{kind}/{val}"
        data = await self.fetcher.get_json(url)
        if not data:
            return []

        claims: list[Claim] = []
        group = f"rdap|{ident.key}"
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        reg_date = _parse(events.get("registration"))

        for ent in data.get("entities", []) or []:
            roles = [r.lower() for r in (ent.get("roles") or [])]
            if not any(r in roles for r in ("registrant", "administrative", "technical", "abuse")):
                continue
            for fn, value in _vcard(ent.get("vcardArray")):
                if self.REDACTION.search(value):
                    continue
                if fn == "fn":
                    kind_id = (
                        IdKind.ORG_NAME if any(
                            t in value.lower()
                            for t in ("ltd", "inc", "llc", "gmbh", "b.v", "corp", "limited")
                        ) else IdKind.PERSON_NAME
                    )
                    claims.append(self.claim(
                        ident, Predicate.REGISTRANT, Identifier(kind_id, value), url,
                        reliability=Reliability.MODERATE, correlation_group=group,
                        observed_at=reg_date,
                        raw={"roles": roles},
                    ))
                elif fn == "email" and "abuse" not in roles:
                    claims.append(self.claim(
                        ident, Predicate.REGISTRANT, Identifier(IdKind.EMAIL, value), url,
                        reliability=Reliability.MODERATE, correlation_group=group,
                        observed_at=reg_date, raw={"roles": roles},
                    ))
                elif fn == "org":
                    claims.append(self.claim(
                        ident, Predicate.REGISTRANT,
                        Identifier(IdKind.ORG_NAME, value), url,
                        reliability=Reliability.MODERATE, correlation_group=group,
                        observed_at=reg_date, raw={"roles": roles},
                    ))
        return claims


def _vcard(arr) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not arr or len(arr) < 2:
        return out
    for item in arr[1]:
        if isinstance(item, list) and len(item) >= 4 and isinstance(item[3], str):
            out.append((item[0].lower(), item[3].strip()))
    return out


@register
class CrtSh(Collector):
    """Certificate transparency. Replaces Censys cert search for the SAN-pivot
    use case at zero cost; Censys still wins on historical scan banners."""

    name = "crtsh"
    source_class = SourceClass.PUBLIC_PROTOCOL
    accepts = (IdKind.DOMAIN,)
    priority = 3

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        url = f"https://crt.sh/?q=%25.{ident.value}&output=json&exclude=expired"
        data = await self.fetcher.get_json(url)
        if not isinstance(data, list):
            return []

        claims: list[Claim] = []
        seen: set[str] = set()
        for rec in data[:500]:
            for name in str(rec.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.").lower()
                if not name or name in seen or name == ident.value:
                    continue
                seen.add(name)
                claims.append(self.claim(
                    ident, Predicate.SHARES_CERT,
                    Identifier(IdKind.DOMAIN, name), url,
                    reliability=Reliability.AUTHORITATIVE,
                    # All SANs on one cert are ONE observation.
                    correlation_group=f"cert|{rec.get('serial_number') or rec.get('id')}",
                    observed_at=_parse(rec.get("not_before")),
                ))
        return claims


@register
class InternetDb(Collector):
    """internetdb.shodan.io: free, keyless, no rate-limit registration.
    Covers the open-ports/hostnames slice of what VirusTotal and Shodan paid
    tiers return for an IP."""

    name = "internetdb"
    source_class = SourceClass.PUBLIC_PROTOCOL
    accepts = (IdKind.IP,)
    priority = 4

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        url = f"https://internetdb.shodan.io/{ident.value}"
        data = await self.fetcher.get_json(url)
        if not data:
            return []
        group = f"internetdb|{ident.value}"
        return [
            self.claim(
                ident, Predicate.CO_HOSTED,
                Identifier(IdKind.DOMAIN, h), url,
                reliability=Reliability.STRONG, correlation_group=group,
            )
            for h in (data.get("hostnames") or [])
        ]


@register
class MnemonicPdns(Collector):
    """mnemonic passive DNS -- the closest keyless analogue to VirusTotal's
    resolutions endpoint. Historical, which VirusTotal's free tier is not."""

    name = "mnemonic_pdns"
    source_class = SourceClass.PUBLIC_PROTOCOL
    accepts = (IdKind.IP, IdKind.DOMAIN)
    priority = 4

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        url = f"https://api.mnemonic.no/pdns/v3/{ident.value}?limit=200"
        data = await self.fetcher.get_json(url)
        rows = (data or {}).get("data") or []

        claims: list[Claim] = []
        for row in rows:
            if row.get("rrtype") not in ("a", "aaaa", "cname"):
                continue
            other = row.get("query") if ident.kind is IdKind.IP else row.get("answer")
            if not other or other == ident.value:
                continue
            kind = IdKind.DOMAIN if _is_domain(other) else IdKind.IP
            claims.append(self.claim(
                ident, Predicate.CO_HOSTED, Identifier(kind, other), url,
                reliability=Reliability.STRONG,
                correlation_group=f"pdns|{ident.value}",
                observed_at=_from_ms(row.get("lastSeenTimestamp")),
                raw={"rrtype": row.get("rrtype")},
            ))
        return claims


@register
class FaviconHash(Collector):
    """mmh3 favicon hashing, done locally.

    Censys and Shodan sell the *index* (hash -> hosts), not the hash function.
    Without a paid index, compute hashes locally and match against a host corpus
    built from CT logs and prior cases -- the corpus is the asset, and it
    accumulates. This is the one substitution that is genuinely worse than the
    paid product on day one and better by month six, because the corpus is
    scoped to the abuse population instead of the whole internet.
    """

    name = "favicon_mmh3"
    source_class = SourceClass.PUBLIC_PROTOCOL
    accepts = (IdKind.DOMAIN,)
    priority = 5

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        try:
            import base64

            import mmh3
        except ImportError:
            return []

        url = f"https://{ident.value}/favicon.ico"
        r = await self.fetcher.get(url, allow_html=True)
        if not r or r.status != 200 or not r.text:
            return []
        b64 = base64.encodebytes(r.text.encode("utf-8", "surrogateescape"))
        h = mmh3.hash(b64)
        return [self.claim(
            ident, Predicate.SHARES_FAVICON,
            Identifier(IdKind.FAVICON_MMH3, str(h)), url,
            reliability=Reliability.STRONG,
            correlation_group=f"favicon|{ident.value}",
        )]


def _is_domain(s: str) -> bool:
    return bool(re.match(r"^[a-z0-9\-._]+\.[a-z]{2,}$", s, re.I))


def _parse(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _from_ms(ms) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc)
    except (TypeError, ValueError):
        return None
