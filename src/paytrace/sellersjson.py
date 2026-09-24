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

import hashlib
import json
import os
import pathlib
import re
import time
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
    # Sovrn does not host sellers.json on its own domain: it publishes at
    # lijit.com, which is also the ad system name that appears in ads.txt.
    "sovrn.com": "https://lijit.com/sellers.json",
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
    """Locations to try, in order.

    When a known location is configured, that IS the location -- the spec's
    default is not tried as well. For google.com the default is
    ``https://google.com/sellers.json``, which does not exist and which
    Google's robots.txt disallows, so every Google seller produced two futile
    requests and two blocked entries that buried the real diagnosis.
    """
    known = SELLERS_JSON_LOCATIONS.get(adsystem.lower())
    if known:
        return [known]
    root = f"https://{adsystem.lower()}/sellers.json"
    return [root, f"https://www.{adsystem.lower()}/sellers.json"]


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

def seller_id_forms(seller_id: str) -> list[str]:
    """Every spelling of one publisher account.

    ads.txt writes `pub-1234…`; a sellers.json may publish the bare digits, or
    `ca-pub-…`. Comparing the strings exactly meant a publisher present in
    Google's file was reported "checked and absent", which reads as a finding.
    """
    raw = str(seller_id).strip()
    bare = re.sub(r"^(?:ca-)?pub-", "", raw, flags=re.I)
    # Only a full 16-digit AdSense publisher id is treated as equivalent to its
    # bare digits. Stripping the prefix from anything shorter would make
    # `pub-1` match a seller whose id is literally `1`.
    if bare == raw or not (bare.isdigit() and len(bare) == 16):
        return [raw]
    return [raw, bare, f"pub-{bare}", f"ca-pub-{bare}"][:4]


def same_seller(a: str, b: str) -> bool:
    """Do two seller ids denote the same account?"""
    def norm(value: str) -> str:
        text = str(value).strip()
        bare = re.sub(r"^(?:ca-)?pub-", "", text, flags=re.I)
        return (bare if bare.isdigit() and len(bare) == 16 else text).lower()

    return norm(a) == norm(b)


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
                if same_seller(s.get("seller_id", ""), seller_id):
                    return _record_from_obj(adsystem, s, source_url)
            return None

    # Streaming path: find the id, then bracket-match the object around it.
    needle = '"seller_id"'
    pattern = "|".join(re.escape(f) for f in seller_id_forms(seller_id))
    for m in re.finditer(pattern, body):
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


async def resolve_seller(fetcher, adsystem: str, seller_id: str,
                         archive: bool = False) -> SellerRecord | None:
    """Fetch and locate a seller, trying every known location for the ad system.

    Falls back to a streaming scan when the document is too large to hold.
    Google's sellers.json is 104 MB, so the ordinary body cap truncated it and
    the payee could never be named -- for the ad system that serves the
    majority of ad-funded sites.
    """
    absent_at: list[str] = []

    # Very large documents go through a local copy: one download per day reused
    # across every account in an ads.txt, instead of one 104 MB transfer per
    # seller. This is also what stops a failed transfer being reported as the
    # seller being absent.
    if adsystem.lower() in LARGE_SELLERS_JSON:
        url = sellers_json_url(adsystem)
        path = await cached_document(fetcher, url)
        if path is not None:
            rec = find_in_file(path, adsystem, seller_id, url)
            if rec:
                return rec
            if hasattr(fetcher, "checked_absent"):
                age = int(time.time() - path.stat().st_mtime)
                fetcher.checked_absent.append(
                    (url, f"checked and absent: seller {seller_id} is not in the "
                          f"local copy ({path.stat().st_size} bytes, {age}s old)"))
            absent_at.append(url)
            if not archive:
                return None
        elif hasattr(fetcher, "blocked"):
            # No local copy AND the download did not complete: fall through to
            # the ordinary candidate loop rather than giving up. Returning here
            # skipped the live attempt entirely.
            fetcher.blocked.append(
                (url, "no local copy; falling back to a direct fetch"))

    for url in candidate_urls(adsystem):
        seen = len(getattr(fetcher, "blocked", ()))
        r = await fetcher.get(url)
        # A response that ARRIVES and is useless -- 403, 429, an error page --
        # was skipped in silence, so a refused candidate looked exactly like one
        # that was never tried. Record it unless something already did.
        if len(getattr(fetcher, "blocked", ())) == seen and (
                r is None or r.status != 200 or not r.text):
            status = "no response" if r is None else f"HTTP {r.status}"
            size = 0 if r is None else len(r.text or "")
            fetcher.blocked.append(
                (url, f"no usable sellers.json: {status}, {size} byte body"))
        truncated = any("truncated" in why
                        for _u, why in list(getattr(fetcher, "blocked", ()))[seen:])
        usable = bool(r and r.status == 200 and r.text)
        if usable:
            rec = find_seller_in_text(r.text, adsystem, seller_id, url)
            if rec:
                return rec
            absent_at.append(url)
            if hasattr(fetcher, "checked_absent"):
                fetcher.checked_absent.append(
                    (url, f"checked and absent: seller {seller_id} is not in the "
                          "current document"))
        # Stream when the ordinary read was truncated OR did not complete at
        # all. Triggering only on truncation meant a 104 MB body that timed out
        # or errored fell straight through to the next candidate -- and for
        # google.com that is https://google.com/sellers.json, which robots.txt
        # disallows, so the payee was never named.
        if truncated or not usable:
            before = len(getattr(fetcher, "blocked", ()))
            rec = await _stream_at(fetcher, url, adsystem, seller_id)
            if rec is None and len(getattr(fetcher, "blocked", ())) == before:
                scanned = (getattr(fetcher, "last_scan", None) or {}).get("bytes")
                # Checked and absent -- NOT blocked. `getattr(f, "x", [])`
                # appended to a throwaway list when the attribute was missing,
                # so this was discarded entirely.
                if hasattr(fetcher, "checked_absent"):
                    fetcher.checked_absent.append(
                        (url, f"checked and absent: seller {seller_id} is not in "
                              f"this document ({scanned} bytes read)"))
                absent_at.append(url)
            if rec:
                # The truncation was recovered: this retrieval DID produce
                # evidence. Leaving it in `blocked` counted a successful
                # fallback as a failed fetch, inflating collection_blocked and
                # reporting the run INCOMPLETE for a gap that was filled.
                fetcher.blocked[:] = [
                    entry for entry in fetcher.blocked
                    if not (entry[0] == url and "truncated" in entry[1])]
                return rec
    # Read successfully and the seller is not there. Often the account was
    # pruned -- ad systems prune, publishers rarely do. But operators also copy
    # ads.txt files wholesale, another operator's lines included, so an account
    # may never have existed in this ad system at all. An archive search costs a
    # CDX query plus snapshot fetches per seller, on a service that is slow and
    # frequently times out, so it is OFF by default: ask for it when the account
    # matters rather than paying it for all 35 lines of an ads.txt.
    if not archive:
        return None
    for url in dict.fromkeys(absent_at):
        rec = await archived_seller(fetcher, url, adsystem, seller_id)
        if rec:
            return rec
    return None


# --------------------------------------------------------------------------- #
# Streaming lookup, for sellers.json documents too large to hold
# --------------------------------------------------------------------------- #

#: Ceiling for a streamed sellers.json. Google's is 104 MB uncompressed, so the
#: ordinary 10 MB body cap truncated it and the payee could never be named.
#: Nothing is retained in scan mode, so this bounds time, not memory.
STREAM_MAX_BYTES = 512 * 1024 * 1024

#: Bytes kept between chunks so a record split across a boundary is still found.
#: sellers.json records are a few hundred bytes; this is generous.
_WINDOW = 64 * 1024


class _RecordScanner:
    """Find one seller record in a stream, without holding the stream."""

    def __init__(self, seller_id: str) -> None:
        self._needles = [f'"{f}"'.encode() for f in seller_id_forms(seller_id)]
        self._buf = b""
        self.record: str | None = None

    def feed(self, chunk: bytes) -> None:
        if self.record is not None:
            return
        self._buf += chunk
        hits = [i for i in (self._buf.find(n) for n in self._needles) if i != -1]
        i = min(hits) if hits else -1
        if i != -1:
            found = _enclosing_object(self._buf, i)
            if found is not None:
                self.record = found
                self._buf = b""
                return
        if len(self._buf) > _WINDOW:
            self._buf = self._buf[-_WINDOW:]


def _enclosing_object(buf: bytes, pos: int) -> str | None:
    """The JSON object containing ``pos``, or None if it is not complete yet."""
    start = buf.rfind(b"{", 0, pos)
    if start == -1:
        return None
    depth, in_str, esc = 0, False, False
    for j in range(start, len(buf)):
        c = buf[j : j + 1]
        if esc:
            esc = False
            continue
        if c == b"\\":
            esc = True
            continue
        if c == b'"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == b"{":
            depth += 1
        elif c == b"}":
            depth -= 1
            if depth == 0:
                return buf[start : j + 1].decode("utf-8", errors="replace")
    return None


async def _stream_at(fetcher, url: str, adsystem: str, seller_id: str):
    scanner = _RecordScanner(seller_id)
    await fetcher.get(url, scanner=scanner.feed, scan_max_bytes=STREAM_MAX_BYTES)
    if scanner.record is None:
        return None
    return find_seller_in_text('{"sellers":[' + scanner.record + "]}",
                               adsystem, seller_id, url)


async def stream_find_seller(fetcher, adsystem: str, seller_id: str):
    """Look up one seller in a sellers.json of any size.

    Streams the document, matches the record as it passes, and keeps only that
    record. The retrieval stays evidenced: the fetcher records the byte count
    and a SHA-256 taken over the stream.
    """
    return await _stream_at(fetcher, sellers_json_url(adsystem), adsystem, seller_id)

#: Snapshots of a sellers.json to try when the current one lacks the seller.
#: Newest first: the closest copy to the ads.txt line is the most relevant.
ARCHIVE_SNAPSHOTS = 3

_CDX = "https://web.archive.org/cdx/search/cdx"


async def archived_seller(fetcher, url: str, adsystem: str, seller_id: str):
    """Find a seller in an ARCHIVED copy of a sellers.json.

    Publishers rarely prune ads.txt; ad systems prune sellers.json regularly.
    So an account declared in ads.txt but absent from the live sellers.json is
    usually one that WAS there -- the relationship is historical, not fictional.
    The archived record carries its snapshot URL as its source, so the report
    shows what it is: evidence of a past relationship.
    """
    cdx = (f"{_CDX}?url={url}&output=json&fl=timestamp,original"
           f"&filter=statuscode:200&collapse=timestamp:6&limit=40")
    rows = await fetcher.get_json(cdx)
    if not isinstance(rows, list) or len(rows) < 2:
        return None
    for ts, original in list(reversed(rows[1:]))[:ARCHIVE_SNAPSHOTS]:
        snapshot = f"https://web.archive.org/web/{ts}id_/{original}"
        scanner = _RecordScanner(seller_id)
        await fetcher.get(snapshot, scanner=scanner.feed,
                          scan_max_bytes=STREAM_MAX_BYTES)
        if scanner.record:
            return find_seller_in_text('{"sellers":[' + scanner.record + "]}",
                                       adsystem, seller_id, snapshot)
    return None

# --------------------------------------------------------------------------- #
# Local copies of the very large sellers.json documents
# --------------------------------------------------------------------------- #

#: Where downloaded sellers.json documents are kept. Google's is 104 MB and
#: every seller lookup re-fetched it: slow, easy to time out, and the cause of
#: a lookup reporting "absent" when the transfer merely failed. One copy per
#: run, reused across the dozens of accounts an ads.txt declares.
SELLERS_CACHE_DIR = pathlib.Path(
    os.environ.get("PAYTRACE_SELLERS_CACHE",
                   pathlib.Path.home() / ".cache" / "paytrace" / "sellers"))

#: How long a downloaded copy stays usable before a refresh is attempted.
SELLERS_CACHE_TTL = 24 * 3600


def _cache_path(url: str) -> pathlib.Path:
    return SELLERS_CACHE_DIR / (hashlib.sha256(url.encode()).hexdigest()[:16] + ".json")


async def cached_document(fetcher, url: str) -> pathlib.Path | None:
    """The local copy of a sellers.json, refreshed when possible.

    A refresh that fails leaves the previous copy in place and returns it: a
    stale answer with known provenance beats no answer, and the report records
    the file's age.
    """
    path = _cache_path(url)
    if path.exists() and time.time() - path.stat().st_mtime < SELLERS_CACHE_TTL:
        return path

    SELLERS_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    part = path.with_suffix(".part")
    try:
        with open(part, "wb") as sink:
            await fetcher.get(url, scanner=sink.write,
                              scan_max_bytes=STREAM_MAX_BYTES)
        if part.stat().st_size > 1024:
            part.replace(path)
            return path
    except OSError:
        pass
    finally:
        if part.exists():
            part.unlink(missing_ok=True)
    return path if path.exists() else None      # stale copy, or nothing


def find_in_file(path: pathlib.Path, adsystem: str, seller_id: str,
                 source_url: str):
    """Scan a local sellers.json without loading it into memory."""
    scanner = _RecordScanner(seller_id)
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            scanner.feed(chunk)
            if scanner.record:
                break
    if not scanner.record:
        return None
    return find_seller_in_text('{"sellers":[' + scanner.record + "]}",
                               adsystem, seller_id, source_url)
