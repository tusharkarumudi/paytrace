"""sellers.json resolution.

Three things break the naive implementation, and all three hit the single most
important ad system.

## 1. The location is not always the domain root

The spec says ``https://{adsystem}/sellers.json``. Google — which pays more
publishers than any other ad system, and is therefore the one lookup that
matters most — publishes at
``https://storage.googleapis.com/adx-rtb-dictionaries/sellers.json``.

A collector that only tries the domain root silently returns nothing for
``google.com``. Nothing raises, nothing logs; the AdSense publisher name, the
best single piece of attribution evidence available, just never appears.

## 2. The files can be enormous

Google's sellers.json contains an entry for every AdSense publisher that has
opted into transparency. It is far past any sane response-size cap, so a
size-limited fetch truncates it, ``json.loads`` then fails on the fragment, and
the collector returns ``None`` — the same silent nothing as a missing file.

So a seller is located by streaming scan rather than by parsing the document:
find the seller ID in the byte stream, then extract only the enclosing JSON
object.

## 3. Sellers are frequently natural persons

An individual AdSense publisher's ``name`` is a person, not a company —
``TRẦN THỊ BÌNH``, not ``Example Media Ltd``. Typing every seller name as an
organization sends the investigation to corporate registries that will never
have a record, and misreports what was actually found.

A named individual with an empty ``domain`` field is its own pattern: a
sole operator monetizing directly, with no corporate layer to trace. That is a
finding, and often the terminus.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum

#: Ad systems that do not serve sellers.json from their domain root.
#: The spec permits a redirect, but several of the largest simply publish
#: elsewhere and a root fetch returns 404 or an HTML page.
SELLERS_JSON_LOCATIONS: dict[str, str] = {
    "google.com": "https://storage.googleapis.com/adx-rtb-dictionaries/sellers.json",
    "doubleclick.net": "https://storage.googleapis.com/adx-rtb-dictionaries/sellers.json",
    "googletagservices.com": (
        "https://storage.googleapis.com/adx-rtb-dictionaries/sellers.json"),
}

#: Ad systems whose sellers.json is large enough that streaming is mandatory.
LARGE_SELLERS_JSON = frozenset({
    "google.com", "doubleclick.net", "googletagservices.com",
    "appnexus.com", "rubiconproject.com", "pubmatic.com", "openx.com",
})

#: Cap for a streaming seller lookup. Far above the general fetch cap, because
#: Google's file legitimately exceeds any reasonable page size.
STREAM_MAX_BYTES = 512 * 1024 * 1024


def sellers_json_url(adsystem: str) -> str:
    """Where this ad system actually publishes sellers.json."""
    return SELLERS_JSON_LOCATIONS.get(
        adsystem.lower(), f"https://{adsystem.lower()}/sellers.json")


def candidate_urls(adsystem: str) -> list[str]:
    """Locations to try, in order. The root is still attempted for ad systems
    that follow the spec."""
    known = SELLERS_JSON_LOCATIONS.get(adsystem.lower())
    root = f"https://{adsystem.lower()}/sellers.json"
    return [known, root] if known else [root, f"https://www.{adsystem.lower()}/sellers.json"]


# --------------------------------------------------------------------------- #
# Seller type
# --------------------------------------------------------------------------- #

class SellerNameKind(StrEnum):
    ORGANIZATION = "organization"
    NATURAL_PERSON = "natural_person"
    AMBIGUOUS = "ambiguous"


#: Legal-form tokens. Presence of one settles it as an organization.
_LEGAL_FORM = re.compile(
    r"\b(inc|incorporated|llc|l\.l\.c|ltd|limited|corp|corporation|co|company|"
    r"gmbh|ug|ag|b\.?v|n\.?v|s\.?a|s\.?l|s\.?r\.?l|sarl|plc|llp|lp|pty|pte|pvt|"
    r"oy|ab|as|aps|sp\.?\s*z\s*o\.?o|s\.?r\.?o|d\.?o\.?o|kft|zrt|sas|sasu|eurl|"
    r"holdings?|group|media|network|digital|technolog\w+|solutions?|ventures?|"
    r"partners?|studios?|labs?|agency|publishing|press|interactive|online|"
    r"cong ty|tnhh|jsc|co\.?,?\s*ltd)\b", re.I)

#: Vietnamese, Indonesian and similar all-caps personal names are common in
#: AdSense records. Distinguishing them matters: a person has no company
#: registry entry, so routing one to GLEIF produces a false negative that looks
#: like a dead end.
_PERSON_HINT = re.compile(r"^[\w\u00C0-\u1EF9'.\-]+(?:\s+[\w\u00C0-\u1EF9'.\-]+){1,4}$")


def classify_seller_name(name: str) -> SellerNameKind:
    """Whether a sellers.json ``name`` denotes an organization or a person."""
    n = (name or "").strip()
    if not n:
        return SellerNameKind.AMBIGUOUS
    if _LEGAL_FORM.search(n):
        return SellerNameKind.ORGANIZATION
    if any(ch.isdigit() for ch in n) or "&" in n:
        return SellerNameKind.ORGANIZATION
    tokens = n.split()
    if 2 <= len(tokens) <= 5 and _PERSON_HINT.match(n):
        return SellerNameKind.NATURAL_PERSON
    return SellerNameKind.AMBIGUOUS


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #

@dataclass
class SellerRecord:
    adsystem: str
    seller_id: str
    name: str = ""
    domain: str = ""
    seller_type: str = ""
    is_confidential: bool = False
    comment: str = ""
    extra: dict = field(default_factory=dict)
    source_url: str = ""

    @property
    def name_kind(self) -> SellerNameKind:
        return classify_seller_name(self.name)

    @property
    def is_natural_person(self) -> bool:
        return self.name_kind is SellerNameKind.NATURAL_PERSON

    @property
    def sole_operator_pattern(self) -> bool:
        """A named individual with no declared domain.

        Common for direct AdSense publishers and usually the terminus: there is
        no corporate layer behind it to trace.
        """
        return self.is_natural_person and not self.domain

    def describe(self) -> str:
        if self.is_confidential:
            return (f"{self.adsystem}/{self.seller_id}: confidential "
                    f"(seller_type={self.seller_type or 'unstated'})")
        bits = [f"{self.adsystem}/{self.seller_id}: {self.name or '(unnamed)'}"]
        bits.append(f"[{self.name_kind.value}]")
        if self.domain:
            bits.append(f"domain={self.domain}")
        else:
            bits.append("no declared domain")
        if self.seller_type:
            bits.append(f"type={self.seller_type}")
        if self.sole_operator_pattern:
            bits.append("— named individual, no corporate layer")
        return " ".join(bits)


def _record_from_obj(adsystem: str, obj: dict, source_url: str) -> SellerRecord:
    # "ext" is deliberately NOT here. It is a publisher-supplied field and has
    # to survive into extra{} so the guard layer can treat it as untrusted
    # prose. Dropping it silently removes an injection surface from view
    # rather than defending against it.
    known = {"seller_id", "name", "domain", "seller_type", "is_confidential",
             "comment"}
    return SellerRecord(
        adsystem=adsystem,
        seller_id=str(obj.get("seller_id", "")),
        name=str(obj.get("name") or ""),
        domain=str(obj.get("domain") or "").lower(),
        seller_type=str(obj.get("seller_type") or "").upper(),
        is_confidential=bool(int(obj.get("is_confidential", 0) or 0)),
        comment=str(obj.get("comment") or ""),
        extra={k: v for k, v in obj.items() if k not in known},
        source_url=source_url,
    )


# --------------------------------------------------------------------------- #
# Lookup
# --------------------------------------------------------------------------- #

def find_seller_in_text(body: str, adsystem: str, seller_id: str,
                        source_url: str = "") -> SellerRecord | None:
    """Locate one seller without parsing the whole document.

    Scans for the seller ID, then walks braces outward to recover the enclosing
    JSON object. Required because the largest files exceed any response-size
    cap, and a truncated document fails to parse as a whole while still
    containing the record being sought.
    """
    if not body:
        return None

    # Fast path: small enough to parse properly.
    if len(body) < 4_000_000:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            for s in data.get("sellers", []):
                if str(s.get("seller_id", "")) == str(seller_id):
                    return _record_from_obj(adsystem, s, source_url)
            return None

    # Streaming path: find the id, then bracket-match the object around it.
    needle = '"seller_id"'
    for m in re.finditer(re.escape(str(seller_id)), body):
        start = body.rfind("{", 0, m.start())
        if start == -1:
            continue
        depth, i = 0, start
        while i < len(body):
            if body[i] == "{":
                depth += 1
            elif body[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        else:
            continue
        chunk = body[start:i + 1]
        if needle not in chunk:
            continue
        try:
            obj = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if str(obj.get("seller_id", "")) == str(seller_id):
            return _record_from_obj(adsystem, obj, source_url)
    return None


async def resolve_seller(fetcher, adsystem: str, seller_id: str) -> SellerRecord | None:
    """Fetch and locate a seller, trying every known location for the ad system."""
    for url in candidate_urls(adsystem):
        r = await fetcher.get(url)
        if not r or r.status != 200 or not r.text:
            continue
        rec = find_seller_in_text(r.text, adsystem, seller_id, url)
        if rec:
            return rec
    return None
