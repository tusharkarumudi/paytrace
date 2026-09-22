"""Sibling discovery and the pivot loop.

The mechanism the pipeline was missing. An investigation seeded on one domain
would collect that domain's artifacts and stop. But the seed is often the
operator's careful public face, and the identity sits on a sibling — a domain
sharing an analytics ID, a hosting IP, a service account, or a favicon — that
was built with less care.

The loop:

    seed --extract--> artifacts + pivot identifiers (analytics, service IDs, IPs)
         --reverse--> sibling domains carrying those identifiers
         --extract--> siblings' artifacts, including their own pivot identifiers
         --repeat---> until no new siblings, or the budget is spent

Each hop is bounded, deduplicated, and decay-weighted by distance from the seed:
a name found on the seed is worth more than one found three pivots away, because
each pivot is another inferential step that could be wrong.

## Why this needs the scoring model underneath it

Fanning out multiplies false-positive risk. A shared Cloudflare IP links a
domain to millions of others; a shared GA4 ID to a genuine portfolio; a shared
Google Fonts request to nothing at all. The loop does not decide which links are
real — it materialises the candidates and lets ``attribution-graph`` score them,
where a low-selectivity identifier contributes almost nothing and a shared
service account contributes a great deal. Without that underneath, a pivot loop
is a machine for manufacturing coincidences.

## Budget and safety

- ``max_siblings`` caps total domains examined (default 25)
- ``max_depth`` caps pivot hops from the seed (default 2)
- Low-selectivity pivots are refused before they fan out, using the same
  holder-count logic that governs portfolio expansion
- CDN and shared-host IPs never seed a sibling pivot — they identify the
  provider, not the operator
"""

from __future__ import annotations

from dataclasses import dataclass, field

from attribution_graph import Claim, Identifier, IdKind

from .adstxt import BOILERPLATE_THRESHOLD
from .extract import Extraction, extract_artifacts
from .fingerprint import cdn_for

#: Distance decay per pivot hop. A claim three hops out is worth ~0.5^3 of the
#: same claim on the seed.
HOP_DECAY = 0.7
MAX_SIBLINGS = 25
MAX_DEPTH = 2

#: Pivot identifier kinds that meaningfully link an operator's own properties.
#: Ordered by how selective they usually are.
PIVOT_KINDS = (
    IdKind.ANALYTICS_ID,   # GA4, service accounts — usually per-operator
    IdKind.GRAVATAR_HASH,  # one email
    IdKind.SELLER_ID,      # ad account — per-operator once boilerplate removed
)


@dataclass
class Sibling:
    domain: str
    depth: int
    via: str                 # the identifier that reached it
    via_kind: str
    extraction: Extraction | None = None

    @property
    def decay(self) -> float:
        return HOP_DECAY ** self.depth


@dataclass
class PivotResult:
    seed: str
    siblings: list[Sibling] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    refused: list[tuple[str, str]] = field(default_factory=list)
    identity_found_on: list[str] = field(default_factory=list)

    @property
    def domains_examined(self) -> list[str]:
        return [self.seed] + [s.domain for s in self.siblings]

    def render(self) -> str:
        L = [f"Pivot expansion from {self.seed}",
             f"  {len(self.siblings)} sibling(s) across "
             f"{max([0] + [s.depth for s in self.siblings])} hop(s)", ""]
        for s in sorted(self.siblings, key=lambda x: (x.depth, x.domain)):
            marker = " *" if s.extraction and s.extraction.yielded_identity else "  "
            L.append(f"  {marker} [{s.depth}] {s.domain}  via {s.via_kind}={s.via}")
        if self.identity_found_on:
            L += ["", "  Identity artifacts recovered from:",
                  *(f"    {d}" for d in self.identity_found_on)]
        if self.refused:
            L += ["", "  Pivots refused (too broad to be evidence):"]
            for ident, why in self.refused[:8]:
                L.append(f"    {ident}: {why}")
        return "\n".join(L)


def _pivotable(ident: Identifier, index) -> tuple[bool, str]:
    """Whether an identifier is selective enough to fan out on."""
    if ident.kind is IdKind.IP:
        cdn = cdn_for(ident.value)
        if cdn:
            return False, f"{cdn} CDN/shared IP — identifies the provider, not the operator"
        return True, ""
    if ident.kind is IdKind.ANALYTICS_ID and index is not None:
        scheme, _, value = ident.value.partition(":")
        n = (index.holders_analytics(scheme, value)
             if hasattr(index, "holders_analytics") else 0)
        if n > BOILERPLATE_THRESHOLD:
            return False, f"{n} holders — a platform artifact, not a portfolio"
    return True, ""


def _siblings_for(ident: Identifier, index, fetcher) -> list[str]:
    """Domains carrying this identifier, via the corpus index."""
    if index is None:
        return []
    if ident.kind is IdKind.ANALYTICS_ID:
        scheme, _, value = ident.value.partition(":")
        if hasattr(index, "domains_for_analytics"):
            # Analytics IDs are case-insensitive; the corpus may store either
            # case. Try the value as-is and upper-cased so a lowercased GA4 ID
            # from a page still matches a corpus keyed on the original.
            out = index.domains_for_analytics(scheme, value)
            if not out and value != value.upper():
                out = index.domains_for_analytics(scheme, value.upper())
            return out
    if ident.kind is IdKind.SELLER_ID and hasattr(index, "sites_for_seller"):
        adsystem, _, sid = ident.value.partition("/")
        return index.sites_for_seller(adsystem, sid)
    return []


async def _fetch(fetcher, url: str):
    """Retrieve a page through either fetcher protocol (see enrich._fetch_text)."""
    getter = getattr(fetcher, "get", None)
    if callable(getter):
        r = getter(url, allow_html=True)
        if hasattr(r, "__await__"):
            r = await r
        if r is None or getattr(r, "status", 0) != 200:
            return None, {}
        return getattr(r, "text", None), dict(getattr(r, "headers", {}) or {})
    get_text = getattr(fetcher, "get_text", None)
    if callable(get_text):
        out = get_text(url)
        if hasattr(out, "__await__"):
            out = await out
        return out, {}
    return None, {}


async def pivot_expand(
    seed: str,
    fetcher,
    *,
    index=None,
    max_siblings: int = MAX_SIBLINGS,
    max_depth: int = MAX_DEPTH,
    probe_sensitive: bool = False,
    audit=None,
) -> PivotResult:
    """Fan from a seed to siblings via shared infrastructure, re-extracting each.

    Returns every claim discovered, decay-weighted by pivot distance. The seed's
    own artifacts are depth 0.
    """
    result = PivotResult(seed=seed)
    seen: set[str] = {seed}
    frontier: list[tuple[str, int, str, str]] = [(seed, 0, "seed", "seed")]

    while frontier and len(result.siblings) < max_siblings:
        domain, depth, via, via_kind = frontier.pop(0)

        body, headers = await _fetch(fetcher, f"https://{domain}/")
        if not body:
            continue

        ex = extract_artifacts(body, domain, f"https://{domain}/", headers=headers)

        if probe_sensitive:
            from .extract import probe_sensitive_paths
            probe = await probe_sensitive_paths(
                fetcher, domain, enabled=True, audit=audit)
            ex.claims.extend(probe.claims)
            for k, vs in probe.artifacts.items():
                for v in vs:
                    ex.add(k, v)

        # Decay every claim by pivot distance from the seed.
        decay = HOP_DECAY ** depth
        for c in ex.claims:
            c.weight = getattr(c, "weight", 1.0) * decay
            c.raw["pivot_depth"] = depth
            if depth > 0:
                c.raw["reached_via"] = f"{via_kind}={via}"
            result.claims.append(c)

        if depth > 0:
            sib = Sibling(domain=domain, depth=depth, via=via,
                          via_kind=via_kind, extraction=ex)
            result.siblings.append(sib)
        if ex.yielded_identity and domain not in result.identity_found_on:
            result.identity_found_on.append(domain)

        if depth >= max_depth:
            continue

        # Fan out on this page's pivot identifiers.
        for ident in ex.pivot_seeds:
            ok, why = _pivotable(ident, index)
            if not ok:
                result.refused.append((ident.value, why))
                continue
            for sib_domain in _siblings_for(ident, index, fetcher):
                sib_domain = sib_domain.lower()
                if sib_domain in seen or len(seen) >= max_siblings:
                    continue
                seen.add(sib_domain)
                frontier.append((sib_domain, depth + 1, ident.value, ident.kind.value))

    return result
