"""Network and content fingerprinting.

Four identifiers, each answering a different question:

    resolved IPs    where does the name point, and is that the origin or a CDN?
    response IP     which address actually served this byte stream?
    content hash    is this byte-for-byte the same document?
    SimHash         is this the same *template* with different content?

The last one is the reason this module exists. Exact hashing tells you two pages
are identical, which they almost never are — a template renders different text
per site. SimHash tells you two pages came from the same codebase despite
differing content, which is what actually identifies a portfolio.

## The CDN problem, stated honestly

Most targets sit behind Cloudflare. The resolved address is then an edge node
shared with millions of unrelated sites, and co-hosting on it means nothing.
This module labels that rather than reporting a shared IP as evidence: an
identifier that resolves into a known CDN range is recorded and demoted, not
silently dropped, so a reviewer can see the origin was concealed rather than
assuming it was never checked.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Known infrastructure ranges
# --------------------------------------------------------------------------- #

#: Published edge ranges for the large CDN and cloud providers. An address in
#: one of these is shared infrastructure: it identifies the provider, not the
#: operator.
CDN_RANGES: dict[str, list[str]] = {
    "cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
        "2c0f:f248::/32",
    ],
    "fastly": ["151.101.0.0/16", "199.232.0.0/16", "2a04:4e42::/32"],
    "akamai": ["23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13"],
    "amazon_cloudfront": ["13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15",
                          "54.192.0.0/16", "205.251.192.0/19"],
    "google": ["34.64.0.0/10", "35.184.0.0/13", "142.250.0.0/15",
               "172.217.0.0/16", "216.58.192.0/19"],
    "vercel": ["76.76.21.0/24"],
}

_PARSED_RANGES: list[tuple[str, object]] = [
    (name, ipaddress.ip_network(cidr))
    for name, cidrs in CDN_RANGES.items() for cidr in cidrs
]


def cdn_for(ip: str) -> str | None:
    """Which shared-infrastructure provider owns this address, if any."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, net in _PARSED_RANGES:
        if addr.version == net.version and addr in net:  # type: ignore[operator]
            return name
    return None


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #

@dataclass
class Resolution:
    host: str
    addresses: list[str] = field(default_factory=list)
    cdn: str | None = None
    resolved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error: str = ""

    @property
    def behind_cdn(self) -> bool:
        return self.cdn is not None

    @property
    def origin_concealed(self) -> bool:
        """Every address is CDN edge, so the origin is not observable here."""
        return bool(self.addresses) and all(cdn_for(a) for a in self.addresses)

    def describe(self) -> str:
        if self.error:
            return f"{self.host}: resolution failed ({self.error})"
        if not self.addresses:
            return f"{self.host}: no addresses"
        base = f"{self.host}: {', '.join(self.addresses[:4])}"
        if self.origin_concealed:
            return (f"{base} — all {self.cdn} edge; origin concealed, and "
                    "co-hosting on these addresses is not evidence")
        return base

    def to_dict(self) -> dict:
        return {"host": self.host, "addresses": self.addresses, "cdn": self.cdn,
                "origin_concealed": self.origin_concealed,
                "resolved_at": self.resolved_at.isoformat(), "error": self.error}


def resolve_host(host: str) -> Resolution:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as e:
        return Resolution(host=host, error=type(e).__name__)
    addrs = sorted({i[4][0] for i in infos})
    providers = {cdn_for(a) for a in addrs} - {None}
    return Resolution(host=host, addresses=addrs,
                      cdn=sorted(providers)[0] if providers else None)


# --------------------------------------------------------------------------- #
# Content hashing
# --------------------------------------------------------------------------- #

def gravatar_hash(email: str) -> str:
    """The Gravatar hash of an email: md5 of the trimmed, lowercased address.

    Canonical implementation. Lets a hash found on one page be tested against a
    candidate email found on another; a match binds the two pages to one person
    without either page revealing the address. MD5 is protocol interop here, not
    a security choice -- Gravatar defines the hash this way.
    """
    return hashlib.md5(  # noqa: S324
        email.strip().lower().encode(), usedforsecurity=False).hexdigest()


def content_sha256(body: bytes | str) -> str:
    raw = body.encode() if isinstance(body, str) else body
    return hashlib.sha256(raw).hexdigest()


def favicon_mmh3(body: bytes) -> int | None:
    """Shodan/Censys-compatible favicon hash. Requires mmh3."""
    try:
        import base64

        import mmh3
    except ImportError:
        return None
    return mmh3.hash(base64.encodebytes(body))


# --------------------------------------------------------------------------- #
# SimHash
# --------------------------------------------------------------------------- #

#: Bits in the SimHash. 64 is our default and gives a usable Hamming
#: distribution.
#:
#: Width matters for interoperability, not just resolution. well-known.dev
#: publishes 48-bit SimHash values (12 hex characters, e.g. d5d3d1c05307), so a
#: 64-bit hash computed here cannot be compared against their index at all --
#: different width, different tokenisation, different seed. Treat an external
#: SimHash as a foreign identifier to match on equality, never as something to
#: compute a Hamming distance against ours.
SIMHASH_BITS = 64

#: Width used by well-known.dev. Recorded so the mismatch is explicit rather
#: than discovered when a comparison silently produces nonsense.
WELLKNOWN_SIMHASH_BITS = 48

#: Below this Hamming distance two documents are near-duplicates. Empirically
#: 0-3 is the same page, 4-12 is the same template with different content, and
#: above ~20 is unrelated. Tune against your own corpus before relying on it.
NEAR_DUPLICATE = 3
SAME_TEMPLATE = 12

_TOKEN = re.compile(r"[a-z0-9]+")
_SCRIPT = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.I | re.S)
_TAG = re.compile(r"<[^>]+>")


def _shingles(text: str, k: int = 4) -> list[str]:
    tokens = _TOKEN.findall(text.lower())
    if len(tokens) < k:
        return tokens
    return [" ".join(tokens[i:i + k]) for i in range(len(tokens) - k + 1)]


def simhash(text: str, bits: int = SIMHASH_BITS, structural: bool = False) -> int:
    """Locality-sensitive hash. Similar documents produce similar values.

    ``structural=True`` hashes the HTML tag sequence with text stripped, which
    is what identifies a shared *codebase*: two sites built from one template
    have near-identical tag structure and completely different prose.
    """
    if structural:
        stripped = _SCRIPT.sub(" ", text)
        source = " ".join(_TAG.findall(stripped))
    else:
        source = _TAG.sub(" ", _SCRIPT.sub(" ", text))

    vector = [0] * bits
    for shingle in _shingles(source):
        h = int.from_bytes(
            hashlib.blake2b(shingle.encode(), digest_size=bits // 8).digest(),
            "big")
        for i in range(bits):
            vector[i] += 1 if (h >> i) & 1 else -1

    out = 0
    for i, v in enumerate(vector):
        if v > 0:
            out |= 1 << i
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def similarity(a: int, b: int, bits: int = SIMHASH_BITS) -> float:
    return 1.0 - hamming(a, b) / bits


@dataclass
class ContentFingerprint:
    url: str
    sha256: str
    simhash_text: int
    simhash_structure: int
    byte_length: int
    response_ip: str = ""
    resolution: Resolution | None = None
    favicon_hash: int | None = None
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "sha256": self.sha256,
            "simhash_text": f"{self.simhash_text:016x}",
            "simhash_structure": f"{self.simhash_structure:016x}",
            "byte_length": self.byte_length,
            "response_ip": self.response_ip,
            "favicon_mmh3": self.favicon_hash,
            "resolution": self.resolution.to_dict() if self.resolution else None,
            "fetched_at": self.fetched_at.isoformat(),
        }


def fingerprint_content(url: str, body: str, *, response_ip: str = "",
                        resolution: Resolution | None = None,
                        favicon: bytes | None = None) -> ContentFingerprint:
    return ContentFingerprint(
        url=url,
        sha256=content_sha256(body),
        simhash_text=simhash(body, structural=False),
        simhash_structure=simhash(body, structural=True),
        byte_length=len(body.encode()),
        response_ip=response_ip,
        resolution=resolution,
        favicon_hash=favicon_mmh3(favicon) if favicon else None,
    )


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #

@dataclass
class FingerprintComparison:
    a: str
    b: str
    identical_bytes: bool
    text_distance: int
    structure_distance: int
    shared_addresses: list[str] = field(default_factory=list)
    shared_cdn_only: bool = False

    @property
    def same_template(self) -> bool:
        """Same codebase, different content — the portfolio signal."""
        return self.structure_distance <= SAME_TEMPLATE

    @property
    def near_duplicate(self) -> bool:
        return self.text_distance <= NEAR_DUPLICATE

    def describe(self) -> str:
        L = [f"{self.a} <-> {self.b}"]
        if self.identical_bytes:
            L.append("  byte-identical documents")
        L.append(f"  text simhash distance:      {self.text_distance}"
                 f"  ({'near-duplicate' if self.near_duplicate else 'different content'})")
        L.append(f"  structural simhash distance: {self.structure_distance}"
                 f"  ({'SAME TEMPLATE' if self.same_template else 'different template'})")
        if self.shared_addresses:
            if self.shared_cdn_only:
                L.append(f"  shared addresses: {len(self.shared_addresses)} — "
                         "all CDN edge, which is not evidence of co-hosting")
            else:
                L.append(f"  shared origin addresses: "
                         f"{', '.join(self.shared_addresses[:4])}")
        if self.same_template and not self.near_duplicate:
            L.append("  -> same codebase, different content: a portfolio signal, "
                     "not a coincidence")
        return "\n".join(L)


def compare_fingerprints(a: ContentFingerprint,
                         b: ContentFingerprint) -> FingerprintComparison:
    shared: list[str] = []
    cdn_only = False
    if a.resolution and b.resolution:
        shared = sorted(set(a.resolution.addresses) & set(b.resolution.addresses))
        cdn_only = bool(shared) and all(cdn_for(x) for x in shared)

    return FingerprintComparison(
        a=a.url, b=b.url,
        identical_bytes=a.sha256 == b.sha256,
        text_distance=hamming(a.simhash_text, b.simhash_text),
        structure_distance=hamming(a.simhash_structure, b.simhash_structure),
        shared_addresses=shared,
        shared_cdn_only=cdn_only,
    )
