"""Mandated-disclosure collectors: where an operator is legally required to
name itself.

The gap this closes. An anonymous downloader site publishes a contact email and
nothing else — anyone can read that off the page, and it identifies nobody. But
the same operator, to distribute a browser extension or an app, or to claim DMCA
safe harbour, has to file a real name with a body that publishes it.

Those filings are the highest-yield name sources for exactly this class of site,
and they are structurally different from everything else in the toolkit: the
operator did not choose to publish them for marketing reasons, they published
because a store policy or a statute required it.

| Source | Compels disclosure via | Yields |
|---|---|---|
| Chrome Web Store | Google trader requirements / EU DSA Art. 30 | publisher, email, address |
| Edge Add-ons | Microsoft publisher agreement | publisher name |
| Firefox AMO | Mozilla developer profile | developer name, homepage |
| Google Play | DSA trader verification | developer name, address, email |
| Apple App Store | DSA trader verification | seller, legal address |
| US Copyright Office DMCA | 17 U.S.C. 512(c)(2) | agent name, organisation, address |

The DMCA directory deserves particular attention for content-downloader sites:
claiming safe harbour requires designating an agent with a real name and postal
address, and the Copyright Office publishes the register. A site whose entire
business is serving other people's media has strong incentive to register, and
registering means being named.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable

from attribution_graph import Claim, Identifier, IdKind, Predicate, Reliability, SourceClass

from ..sellersjson import SellerNameKind, classify_seller_name
from .base import Collector, register

# --------------------------------------------------------------------------- #
# Browser extension stores
# --------------------------------------------------------------------------- #

_CHROME_ID = re.compile(r"^[a-p]{32}$")
_EDGE_ID = re.compile(r"^[a-p]{32}$")


@register
class ExtensionStoreDeveloper(Collector):
    """Publisher identity behind a browser extension.

    Extension IDs were already being extracted from site markup and then
    discarded -- ``IdKind.URL`` was emitted and no collector accepted it. This
    closes that loop, and it is often the single strongest name source for a
    site that otherwise publishes only a Gmail address.

    Store listings carry an "Offered by" publisher, a support email, and — for
    developers who have completed EU trader verification — a legal name and
    postal address that the store is required to display.
    """

    name = "extension_store_developer"
    source_class = SourceClass.PLATFORM_PUBLIC_API
    accepts = (IdKind.URL,)
    priority = 2

    STORES = {
        "chrome": "https://chromewebstore.google.com/detail/{id}",
        "edge": "https://microsoftedge.microsoft.com/addons/detail/{id}",
        "firefox": "https://addons.mozilla.org/api/v5/addons/addon/{id}/",
    }

    #: Patterns for the publisher block in each store's markup.
    _OFFERED_BY = re.compile(
        r"(?:Offered by|Published by|Developed by|Publisher)[:\s]*"
        r"([^\n<|]{2,80})", re.I)
    _TRADER = re.compile(
        r"(?:Trader|Legal name|Registered name|Company)[:\s]*([^\n<|]{2,80})", re.I)
    _EMAIL = re.compile(r"[\w.+\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,4}")
    _ADDRESS = re.compile(
        r"(?:Address|Registered address)[:\s]*([^\n<]{10,160})", re.I)

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        m = re.match(r"^ext:(chrome|edge|firefox)/([\w\-.]+)$", ident.value)
        if not m:
            return []
        store, ext_id = m.group(1), m.group(2)
        url = self.STORES[store].format(id=ext_id)

        r = await self.fetcher.get(url, allow_html=True)
        if not r or r.status != 200 or not r.text:
            return []

        group = f"extension|{store}|{ext_id}"
        claims: list[Claim] = []

        if store == "firefox":
            claims.extend(self._parse_amo(r.text, ident, url, group))
            return claims

        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "\n", r.text))

        for pattern, pred, rel, label in (
            (self._TRADER, Predicate.LEGAL_NAME, Reliability.AUTHORITATIVE, "trader"),
            (self._OFFERED_BY, Predicate.OPERATES, Reliability.STRONG, "offered_by"),
        ):
            mm = pattern.search(text)
            if not mm:
                continue
            value = mm.group(1).strip(" .,-")
            if not value or len(value) < 2:
                continue
            kind = (IdKind.PERSON_NAME
                    if classify_seller_name(value) is SellerNameKind.NATURAL_PERSON
                    else IdKind.ORG_NAME)
            claims.append(self.claim(
                ident, pred, Identifier(kind, value), url,
                reliability=rel, correlation_group=group,
                raw={"store": store, "field": label,
                     "name_kind": kind.value,
                     "basis": "store-displayed publisher identity"}))

        addr = self._ADDRESS.search(text)
        if addr:
            claims.append(self.claim(
                ident, Predicate.REGISTERED_ADDRESS,
                Identifier(IdKind.POSTAL_ADDRESS, addr.group(1).strip()), url,
                reliability=Reliability.AUTHORITATIVE, correlation_group=group,
                raw={"store": store, "basis": "trader address required for EU distribution"}))

        for em in list(dict.fromkeys(self._EMAIL.findall(text)))[:3]:
            if em.lower().endswith(("google.com", "microsoft.com", "mozilla.org")):
                continue
            claims.append(self.claim(
                ident, Predicate.PROFILE_BINDING, Identifier(IdKind.EMAIL, em.lower()),
                url, reliability=Reliability.STRONG, correlation_group=group,
                raw={"store": store, "field": "support_email"}))

        return claims

    def _parse_amo(self, body: str, ident: Identifier, url: str,
                   group: str) -> list[Claim]:
        """Firefox AMO exposes a JSON API, so parse it properly."""
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        claims: list[Claim] = []
        for author in data.get("authors", [])[:5]:
            nm = author.get("name") or author.get("display_name")
            if not nm:
                continue
            kind = (IdKind.PERSON_NAME
                    if classify_seller_name(nm) is SellerNameKind.NATURAL_PERSON
                    else IdKind.ORG_NAME)
            claims.append(self.claim(
                ident, Predicate.OPERATES, Identifier(kind, nm), url,
                reliability=Reliability.STRONG, correlation_group=group,
                raw={"store": "firefox", "author_id": author.get("id")}))
            if author.get("homepage"):
                dom = re.sub(r"^https?://(www\.)?", "",
                             str(author["homepage"])).split("/")[0].lower()
                if "." in dom:
                    claims.append(self.claim(
                        ident, Predicate.OPERATES, Identifier(IdKind.DOMAIN, dom),
                        url, reliability=Reliability.MODERATE,
                        correlation_group=group))
        return claims


# --------------------------------------------------------------------------- #
# App stores
# --------------------------------------------------------------------------- #

@register
class AppStoreDeveloper(Collector):
    """Developer identity behind a mobile app.

    Since the DSA, both Google Play and the App Store display verified trader
    details — legal name, address, email — for developers distributing in the
    EU. That is a stronger disclosure than anything on the operator's own site,
    because the store verified it rather than accepting it.
    """

    name = "app_store_developer"
    source_class = SourceClass.PLATFORM_PUBLIC_API
    accepts = (IdKind.URL,)
    priority = 3

    _TRADER_BLOCK = re.compile(
        r"(?:Trader|Verified trader|Developer|Seller)[:\s]*([^\n<|]{2,100})", re.I)
    _ADDRESS = re.compile(r"(?:Address)[:\s]*([^\n<]{10,200})", re.I)
    _EMAIL = re.compile(r"[\w.+\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,4}")

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        m = re.match(r"^app:(play|appstore)/([\w\-.]+)$", ident.value)
        if not m:
            return []
        store, app_id = m.group(1), m.group(2)
        url = (f"https://play.google.com/store/apps/details?id={app_id}&hl=en&gl=DE"
               if store == "play" else f"https://apps.apple.com/de/app/id{app_id}")

        r = await self.fetcher.get(url, allow_html=True)
        if not r or r.status != 200 or not r.text:
            return []

        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "\n", r.text))
        group = f"app|{store}|{app_id}"
        claims: list[Claim] = []

        mm = self._TRADER_BLOCK.search(text)
        if mm:
            value = mm.group(1).strip(" .,-")
            kind = (IdKind.PERSON_NAME
                    if classify_seller_name(value) is SellerNameKind.NATURAL_PERSON
                    else IdKind.ORG_NAME)
            claims.append(self.claim(
                ident, Predicate.LEGAL_NAME, Identifier(kind, value), url,
                reliability=Reliability.AUTHORITATIVE, correlation_group=group,
                raw={"store": store, "basis": "DSA trader verification",
                     "name_kind": kind.value}))

        addr = self._ADDRESS.search(text)
        if addr:
            claims.append(self.claim(
                ident, Predicate.REGISTERED_ADDRESS,
                Identifier(IdKind.POSTAL_ADDRESS, addr.group(1).strip()), url,
                reliability=Reliability.AUTHORITATIVE, correlation_group=group))

        for em in list(dict.fromkeys(self._EMAIL.findall(text)))[:2]:
            if em.lower().endswith(("google.com", "apple.com")):
                continue
            claims.append(self.claim(
                ident, Predicate.PROFILE_BINDING, Identifier(IdKind.EMAIL, em.lower()),
                url, reliability=Reliability.STRONG, correlation_group=group))
        return claims


# --------------------------------------------------------------------------- #
# DMCA designated agent
# --------------------------------------------------------------------------- #

@register
class DmcaAgent(Collector):
    """US Copyright Office designated-agent directory.

    The highest-yield name source for a site whose business is serving other
    people's media, and the least used.

    Claiming safe harbour under 17 U.S.C. 512(c) requires designating an agent
    with the Copyright Office and providing a name, organisation and postal
    address, all of which the Office publishes in a searchable directory. A
    downloader or viewer site faces constant takedown pressure, so the incentive
    to register is strong — and registering means being named.
    """

    name = "dmca_agent"
    source_class = SourceClass.PUBLIC_REGISTRY
    accepts = (IdKind.DOMAIN, IdKind.ORG_NAME, IdKind.PERSON_NAME)
    priority = 3

    SEARCH = "https://dmca.copyright.gov/osp/publish/search.html?search={q}"
    #: The directory is a JS application; the JSON endpoint behind it is what
    #: actually answers. Confirm against the current deployment before relying
    #: on the shape.
    API = "https://dmca.copyright.gov/osp/api/service-providers?search={q}"

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        q = ident.value
        data = await self.fetcher.get_json(self.API.format(q=q))
        if not data:
            return []

        records = data if isinstance(data, list) else data.get("results", [])
        claims: list[Claim] = []

        for rec in records[:5]:
            org = (rec.get("serviceProviderName") or rec.get("organization")
                   or rec.get("name"))
            agent = (rec.get("agentName") or rec.get("designatedAgent"))
            addr = (rec.get("address") or rec.get("fullAddress"))
            email = rec.get("email")
            group = f"dmca|{rec.get('id') or org or q}"
            url = self.SEARCH.format(q=q)

            if org:
                claims.append(self.claim(
                    ident, Predicate.LEGAL_NAME, Identifier(IdKind.ORG_NAME, org),
                    url, reliability=Reliability.AUTHORITATIVE,
                    correlation_group=group,
                    raw={"basis": "DMCA designated-agent filing, 17 U.S.C. 512(c)(2)"}))
            if agent:
                kind = (IdKind.PERSON_NAME
                        if classify_seller_name(agent) is SellerNameKind.NATURAL_PERSON
                        else IdKind.ORG_NAME)
                claims.append(self.claim(
                    Identifier(kind, agent), Predicate.OFFICER_OF,
                    Identifier(IdKind.ORG_NAME, org or q), url,
                    reliability=Reliability.AUTHORITATIVE, correlation_group=group,
                    raw={"role": "DMCA designated agent"}))
            if addr:
                claims.append(self.claim(
                    Identifier(IdKind.ORG_NAME, org or q),
                    Predicate.REGISTERED_ADDRESS,
                    Identifier(IdKind.POSTAL_ADDRESS, str(addr)), url,
                    reliability=Reliability.AUTHORITATIVE, correlation_group=group))
            if email:
                claims.append(self.claim(
                    ident, Predicate.PROFILE_BINDING,
                    Identifier(IdKind.EMAIL, str(email).lower()), url,
                    reliability=Reliability.AUTHORITATIVE, correlation_group=group))
        return claims


# --------------------------------------------------------------------------- #
# Extraction helpers
# --------------------------------------------------------------------------- #

_STORE_LINKS = {
    "chrome": re.compile(
        r"chromewebstore\.google\.com/detail/(?:[\w\-]+/)?([a-p]{32})", re.I),
    "edge": re.compile(
        r"microsoftedge\.microsoft\.com/addons/detail/(?:[\w\-]+/)?([a-p]{32})", re.I),
    "firefox": re.compile(
        r"addons\.mozilla\.org/[\w\-/]*firefox/addon/([\w\-]+)", re.I),
}
_APP_LINKS = {
    "play": re.compile(r"play\.google\.com/store/apps/details\?id=([\w.]+)", re.I),
    "appstore": re.compile(r"apps\.apple\.com/[\w/\-]*id(\d{6,12})", re.I),
}


def extract_store_identifiers(html: str) -> list[str]:
    """Pull extension and app identifiers out of site markup.

    These were previously extracted as opaque URLs and never followed. Each one
    is a link to a mandated disclosure.
    """
    out: list[str] = []
    for store, pat in _STORE_LINKS.items():
        for m in pat.finditer(html):
            out.append(f"ext:{store}/{m.group(1)}")
    for store, pat in _APP_LINKS.items():
        for m in pat.finditer(html):
            out.append(f"app:{store}/{m.group(1)}")
    return list(dict.fromkeys(out))
