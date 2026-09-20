"""Additional entity collectors: OpenCorporates, code hosts, package registries,
trademark offices.

Package-registry provenance is the underrated one here. An npm or PyPI package
names its maintainers, its repository, and often its funding target, and those
bindings are published by the publisher rather than inferred. For supply-chain
attribution -- who actually controls this dependency -- it is frequently the
shortest path.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from datetime import datetime, timezone

from attribution_graph import Claim, Identifier, IdKind, Predicate, Reliability, SourceClass

from .base import Collector, register

# --------------------------------------------------------------------------- #
# OpenCorporates
# --------------------------------------------------------------------------- #

def _auth(key: str | None) -> dict[str, str] | None:
    """OpenCorporates credentials as a header, never as a query parameter.

    The token used to be interpolated into the URL, which put it into evidence
    captures, cache keys, audit entries and exception text. Evidence packages
    are built to be handed to someone else.
    """
    return {"Authorization": f"Token token={key}"} if key else None


@register
class OpenCorporates(Collector):
    """Widest jurisdictional coverage of any single corporate API.

    Terms permit lookup, not bulk re-publication -- so this is a per-identifier
    collector and its output is deliberately not written into the selectivity
    corpus.
    """

    name = "opencorporates"
    source_class = SourceClass.PUBLIC_REGISTRY
    accepts = (IdKind.ORG_NAME, IdKind.COMPANY_NUMBER)
    needs_key = "OPENCORPORATES_API_KEY"
    priority = 2

    BASE = "https://api.opencorporates.com/v0.4"

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        key = os.environ.get(self.needs_key or "")
        if not key:
            return []

        if ident.kind is IdKind.COMPANY_NUMBER:
            juris, num = (ident.value.split("/", 1) + [""])[:2]
            if juris in ("unknown", ""):
                return []
            # The token used to ride in the query string, which meant it was
            # written into evidence captures, the cache key, the audit log and
            # any exception text. Evidence packages are designed to be shared.
            url = f"{self.BASE}/companies/{juris.lower()}/{num}"
            data = await self.fetcher.get_json(url, headers=_auth(key))
            companies = [{"company": (data or {}).get("results", {}).get("company", {})}]
        else:
            q = ident.value.replace(" ", "+")
            url = f"{self.BASE}/companies/search?q={q}&per_page=5"
            data = await self.fetcher.get_json(url, headers=_auth(key))
            companies = ((data or {}).get("results") or {}).get("companies", [])

        claims: list[Claim] = []
        for wrapper in companies:
            c = wrapper.get("company") or {}
            juris = c.get("jurisdiction_code")
            num = c.get("company_number")
            if not (juris and num):
                continue
            cn = Identifier(IdKind.COMPANY_NUMBER, f"{juris}/{num}")
            group = f"opencorporates|{juris}/{num}"
            src = c.get("opencorporates_url", url)

            if c.get("name"):
                claims.append(self.claim(
                    cn, Predicate.LEGAL_NAME, Identifier(IdKind.ORG_NAME, c["name"]), src,
                    # Aggregated from a registry, not the registry itself.
                    reliability=Reliability.STRONG, correlation_group=group,
                    observed_at=_iso(c.get("incorporation_date")),
                    raw={"status": c.get("current_status")},
                ))
            for prev in c.get("previous_names", []) or []:
                if prev.get("company_name"):
                    claims.append(self.claim(
                        cn, Predicate.LEGAL_NAME,
                        Identifier(IdKind.ORG_NAME, prev["company_name"]), src,
                        reliability=Reliability.STRONG, correlation_group=group,
                        observed_at=_iso(prev.get("end_date")), raw={"former": True},
                    ))
            if juris:
                claims.append(self.claim(
                    cn, Predicate.INCORPORATED_IN, juris.upper(), src,
                    reliability=Reliability.STRONG, correlation_group=group,
                ))
            addr = (c.get("registered_address_in_full") or "").strip()
            if addr:
                claims.append(self.claim(
                    cn, Predicate.REGISTERED_ADDRESS,
                    Identifier(IdKind.POSTAL_ADDRESS, addr), src,
                    reliability=Reliability.STRONG, correlation_group=group,
                ))
            for off in (c.get("officers") or [])[:25]:
                o = off.get("officer") or {}
                nm = o.get("name")
                if not nm or o.get("end_date"):
                    continue
                is_org = bool(re.search(
                    r"\b(ltd|limited|llc|inc|gmbh|b\.?v|corp|plc|s\.?a)\b", nm, re.I))
                claims.append(self.claim(
                    Identifier(IdKind.ORG_NAME if is_org else IdKind.PERSON_NAME, nm),
                    Predicate.OFFICER_OF, cn, src,
                    reliability=Reliability.STRONG,
                    # All officers of one company are one filing observation.
                    correlation_group=f"{group}|officers",
                    observed_at=_iso(o.get("start_date")),
                    raw={"position": o.get("position")},
                ))
        return claims


# --------------------------------------------------------------------------- #
# Code hosts (organization-level)
# --------------------------------------------------------------------------- #

@register
class CodeHostOrg(Collector):
    """Organization-level attribution on GitHub and GitLab.

    Scoped to organizations, not individual contributors: an org profile is a
    published corporate identity, whereas walking the member list is persona
    enumeration and belongs behind the entity-type gate.
    """

    name = "code_host_org"
    source_class = SourceClass.PLATFORM_PUBLIC_API
    accepts = (IdKind.ORG_NAME, IdKind.HANDLE, IdKind.DOMAIN)
    priority = 3

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        claims: list[Claim] = []
        candidates: list[str] = []

        if ident.kind is IdKind.HANDLE and ident.value.startswith("github:"):
            candidates = [ident.value.split(":", 1)[1]]
        elif ident.kind is IdKind.DOMAIN:
            candidates = [ident.value.split(".")[0]]
        elif ident.kind is IdKind.ORG_NAME:
            candidates = [re.sub(r"[^a-z0-9-]", "", ident.value.lower().replace(" ", "-"))]

        hdr = {"Accept": "application/vnd.github+json"}
        if os.environ.get("GITHUB_TOKEN"):
            hdr["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"

        for login in candidates[:3]:
            if len(login) < 3:
                continue
            url = f"https://api.github.com/orgs/{login}"
            data = await self.fetcher.get_json(url, headers=hdr)
            if not data or data.get("type") != "Organization":
                continue
            org_handle = Identifier(IdKind.HANDLE, f"github:{login}")
            group = f"github_org|{login}"

            if data.get("name"):
                claims.append(self.claim(
                    org_handle, Predicate.LEGAL_NAME,
                    Identifier(IdKind.ORG_NAME, data["name"]), url,
                    reliability=Reliability.MODERATE, correlation_group=group,
                ))
            if data.get("blog"):
                dom = re.sub(r"^https?://(www\.)?", "", data["blog"]).split("/")[0].lower()
                if "." in dom:
                    claims.append(self.claim(
                        org_handle, Predicate.OPERATES,
                        Identifier(IdKind.DOMAIN, dom), url,
                        reliability=Reliability.MODERATE, correlation_group=group,
                    ))
            if data.get("email"):
                claims.append(self.claim(
                    org_handle, Predicate.PROFILE_BINDING,
                    Identifier(IdKind.EMAIL, data["email"]), url,
                    reliability=Reliability.MODERATE, correlation_group=group,
                ))
            if data.get("location"):
                claims.append(self.claim(
                    org_handle, Predicate.REGISTERED_ADDRESS,
                    Identifier(IdKind.POSTAL_ADDRESS, data["location"]), url,
                    reliability=Reliability.WEAK, correlation_group=group,
                ))
        return claims


# --------------------------------------------------------------------------- #
# Package registries
# --------------------------------------------------------------------------- #

@register
class PackageRegistry(Collector):
    """npm / PyPI / crates.io publisher provenance.

    Publisher-declared bindings between a package, a repository and a
    maintainer account. High value for supply-chain attribution because the
    declaration is made by the publisher rather than inferred by us.
    """

    name = "package_registry"
    source_class = SourceClass.PLATFORM_PUBLIC_API
    accepts = (IdKind.ORG_NAME, IdKind.DOMAIN, IdKind.HANDLE)
    priority = 4

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        pkg = (
            ident.value.split(".")[0] if ident.kind is IdKind.DOMAIN
            else ident.value.split(":")[-1]
        )
        if len(pkg) < 3:
            return []

        claims: list[Claim] = []
        for registry, url, parse in (
            ("npm", f"https://registry.npmjs.org/{pkg}", _parse_npm),
            ("pypi", f"https://pypi.org/pypi/{pkg}/json", _parse_pypi),
            ("crates", f"https://crates.io/api/v1/crates/{pkg}", _parse_crates),
        ):
            data = await self.fetcher.get_json(url)
            if not data:
                continue
            group = f"{registry}|{pkg}"
            for kind, value, pred, rel in parse(data):
                claims.append(self.claim(
                    Identifier(IdKind.URL, f"pkg:{registry}/{pkg}"),
                    pred, Identifier(kind, value), url,
                    reliability=rel, correlation_group=group,
                ))
        return claims


def _repo_domain(url: str) -> str | None:
    m = re.search(r"https?://(?:www\.)?([\w.-]+)/", url + "/")
    return m.group(1).lower() if m else None


def _parse_npm(d: dict):
    out = []
    for m in (d.get("maintainers") or [])[:10]:
        if m.get("email"):
            out.append((IdKind.EMAIL, m["email"], Predicate.PROFILE_BINDING, Reliability.STRONG))
        if m.get("name"):
            out.append((IdKind.HANDLE, f"npm:{m['name']}", Predicate.PROFILE_BINDING,
                        Reliability.STRONG))
    repo = ((d.get("repository") or {}).get("url") or "")
    if repo and (dom := _repo_domain(repo)):
        out.append((IdKind.DOMAIN, dom, Predicate.OPERATES, Reliability.MODERATE))
    return out


def _parse_pypi(d: dict):
    info = d.get("info") or {}
    out = []
    for field, kind in (("author_email", IdKind.EMAIL), ("maintainer_email", IdKind.EMAIL)):
        v = (info.get(field) or "").strip()
        if v and "@" in v:
            out.append((kind, re.sub(r".*<|>.*", "", v).strip(),
                        Predicate.PROFILE_BINDING, Reliability.STRONG))
    for field in ("author", "maintainer"):
        v = (info.get(field) or "").strip()
        if v and len(v) > 2:
            out.append((IdKind.PERSON_NAME, v, Predicate.PROFILE_BINDING, Reliability.WEAK))
    for v in (info.get("project_urls") or {}).values():
        if v and (dom := _repo_domain(str(v))):
            out.append((IdKind.DOMAIN, dom, Predicate.OPERATES, Reliability.MODERATE))
    return out


def _parse_crates(d: dict):
    out = []
    c = d.get("crate") or {}
    for field in ("repository", "homepage"):
        if c.get(field) and (dom := _repo_domain(c[field])):
            out.append((IdKind.DOMAIN, dom, Predicate.OPERATES, Reliability.MODERATE))
    return out


# --------------------------------------------------------------------------- #
# Trademark
# --------------------------------------------------------------------------- #

@register
class PersonNameRoutes(Collector):
    """Routes that accept a natural-person name.

    Before this, ``PERSON_NAME`` was accepted by exactly one collector
    (sanctions screening, which almost never hits), so resolving a payee to an
    individual was a dead end. Corporate registries are the wrong instrument
    for a sole operator; these are the right ones.
    """

    name = "person_name_routes"
    source_class = SourceClass.PLATFORM_PUBLIC_API
    accepts = (IdKind.PERSON_NAME,)
    priority = 3

    VKS = "https://keys.openpgp.org/vks/v1/by-email/{email}"
    NPM = "https://registry.npmjs.org/-/v1/search?text=author:{q}&size=10"
    PYPI = "https://pypi.org/search/?q={q}"

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        from ..enrich import name_variants

        claims: list[Claim] = []
        variants = name_variants(ident.value)[:4]

        # npm indexes the author field, so a name is directly queryable.
        for v in variants:
            url = self.NPM.format(q=v.replace(" ", "%20"))
            data = await self.fetcher.get_json(url)
            for obj in (data or {}).get("objects", [])[:5]:
                pkg = obj.get("package", {})
                pub = (pkg.get("publisher") or {}).get("username")
                if not pkg.get("name"):
                    continue
                group = f"npm_author|{v}"
                claims.append(self.claim(
                    ident, Predicate.OPERATES,
                    Identifier(IdKind.URL, f"pkg:npm/{pkg['name']}"), url,
                    reliability=Reliability.WEAK, correlation_group=group,
                    raw={"matched_variant": v, "publisher": pub}))
                if pub:
                    claims.append(self.claim(
                        ident, Predicate.PROFILE_BINDING,
                        Identifier(IdKind.HANDLE, f"npm:{pub}"), url,
                        reliability=Reliability.WEAK, correlation_group=group))
                email = (pkg.get("author") or {}).get("email")
                if email:
                    claims.append(self.claim(
                        ident, Predicate.PROFILE_BINDING,
                        Identifier(IdKind.EMAIL, email.lower()), url,
                        reliability=Reliability.MODERATE,
                        correlation_group=group))
        return claims


@register
class UsptoTrademark(Collector):
    """Brand -> owning legal entity. Underused and high selectivity: a mark
    registration names a real applicant with a real address, and operators who
    protect a brand across a portfolio register it once."""

    name = "uspto_trademark"
    source_class = SourceClass.PUBLIC_REGISTRY
    accepts = (IdKind.ORG_NAME,)
    needs_key = "USPTO_API_KEY"
    priority = 4

    BASE = "https://api.uspto.gov/api/v1/trademark"

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        key = os.environ.get(self.needs_key or "")
        if not key:
            return []
        url = f"{self.BASE}/search?query={ident.value.replace(' ', '%20')}&rows=5"
        data = await self.fetcher.get_json(url, headers={"X-API-KEY": key})
        claims: list[Claim] = []
        for rec in (data or {}).get("results", [])[:5]:
            owner = rec.get("ownerName") or rec.get("owner")
            serial = rec.get("serialNumber")
            if not (owner and serial):
                continue
            group = f"uspto|{serial}"
            claims.append(self.claim(
                ident, Predicate.SAME_AS, Identifier(IdKind.ORG_NAME, owner), url,
                reliability=Reliability.AUTHORITATIVE, correlation_group=group,
                observed_at=_iso(rec.get("filingDate")),
                raw={"mark": rec.get("markLiteralElements"), "serial": serial},
            ))
            if rec.get("ownerAddress"):
                claims.append(self.claim(
                    Identifier(IdKind.ORG_NAME, owner), Predicate.REGISTERED_ADDRESS,
                    Identifier(IdKind.POSTAL_ADDRESS, rec["ownerAddress"]), url,
                    reliability=Reliability.AUTHORITATIVE, correlation_group=group,
                ))
        return claims


def _iso(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y%m%d"):
        try:
            return datetime.strptime(s[:len(fmt) + 2].rstrip("Z"), fmt).replace(
                tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
