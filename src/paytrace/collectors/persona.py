"""Persona / operator collectors. Optional extra, off by default.

    pip install "paytrace[persona]"

Install alone does not enable these. Two gates must both be open:

1. The case file must list ``Person`` or ``Persona`` in ``entity_types_allowed``.
2. The collector must be named explicitly in ``persona_collectors``.

That is a deliberate two-key design rather than a single flag. A case scoped to
``Company`` cannot accidentally start enumerating people because someone passed
``--collectors all``, and enabling one persona collector does not enable the
rest.

The underlying capabilities are not novel — holehe, maigret, WhatsMyName and
Gravatar lookups are all popular, maintained, trivially installable tools. What
these wrappers add is integration with the scoring model, which is mostly a
*restraining* influence: handle reuse across N platforms lands in one
correlation group and therefore cannot exceed the single-source confidence cap,
no matter how many hits an enumerator returns.

``username_expand`` is treated differently from the others and is worth
understanding before you enable it. The rest take an identifier you already hold
and query one named service. Enumeration takes a bare handle and sweeps hundreds
of sites — that is a profile-building operation rather than a lookup, and by the
scoring model's own logic its output is worth very little: every hit joins the
same correlation group, so five hundred matches score the same as one. It
requires its own flag and is capped.

The ``pivot_radius`` cap still applies to all of them. It is what stops an
investigation of a scraper network from walking into the personal life of a
contributor who once committed to a shared repository.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
from collections import Counter
from collections.abc import Iterable
from datetime import datetime

from attribution_graph import Claim, Identifier, IdKind, Predicate, Reliability, SourceClass

from .base import Collector, register

# --------------------------------------------------------------------------- #
# Gravatar
# --------------------------------------------------------------------------- #

@register
class Gravatar(Collector):
    name = "gravatar"
    source_class = SourceClass.PLATFORM_PUBLIC_API
    accepts = (IdKind.EMAIL, IdKind.GRAVATAR_HASH)
    priority = 2

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        if ident.kind is IdKind.EMAIL:
            h = hashlib.sha256(ident.value.strip().lower().encode()).hexdigest()
            subject = ident
        else:
            h = ident.value
            subject = ident

        url = f"https://gravatar.com/{h}.json"
        data = await self.fetcher.get_json(url)
        if not data:
            return []

        claims: list[Claim] = []
        group = f"gravatar|{h}"
        for entry in data.get("entry", []):
            hash_id = Identifier(IdKind.GRAVATAR_HASH, h)
            if ident.kind is IdKind.EMAIL:
                claims.append(self.claim(
                    subject, Predicate.SHARES_GRAVATAR, hash_id, url,
                    reliability=Reliability.AUTHORITATIVE, correlation_group=group,
                ))
            display = entry.get("displayName") or (entry.get("name") or {}).get("formatted")
            if display:
                claims.append(self.claim(
                    hash_id, Predicate.PROFILE_BINDING,
                    Identifier(IdKind.PERSON_NAME, display), url,
                    reliability=Reliability.MODERATE, correlation_group=group,
                ))
            for acct in entry.get("accounts", []) or []:
                sn, un = acct.get("shortname"), acct.get("username")
                if sn and un:
                    claims.append(self.claim(
                        hash_id, Predicate.PROFILE_BINDING,
                        Identifier(IdKind.HANDLE, f"{sn}:{un}"), url,
                        reliability=Reliability.STRONG, correlation_group=group,
                    ))
        return claims


# --------------------------------------------------------------------------- #
# GitHub
# --------------------------------------------------------------------------- #

@register
class GitHubIntel(Collector):
    name = "github_intel"
    source_class = SourceClass.PLATFORM_PUBLIC_API
    accepts = (IdKind.HANDLE, IdKind.EMAIL)
    needs_key = "GITHUB_TOKEN"
    priority = 2

    API = "https://api.github.com"

    def _hdr(self) -> dict:
        tok = os.environ.get("GITHUB_TOKEN")
        h = {"Accept": "application/vnd.github+json"}
        if tok:
            h["Authorization"] = f"Bearer {tok}"
        return h

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        if ident.kind is IdKind.HANDLE:
            if not ident.value.startswith("github:"):
                return []
            login = ident.value.split(":", 1)[1]
        else:
            # noreply address encodes the login directly
            m = re.match(r"^(?:\d+\+)?([\w\-]+)@users\.noreply\.github\.com$", ident.value)
            if not m:
                return []
            login = m.group(1)

        handle = Identifier(IdKind.HANDLE, f"github:{login}")
        claims: list[Claim] = []

        # -- profile ------------------------------------------------------- #
        purl = f"{self.API}/users/{login}"
        prof = await self.fetcher.get_json(purl, headers=self._hdr())
        if not prof:
            return []
        group = f"github_profile|{login}"

        if prof.get("name"):
            claims.append(self.claim(
                handle, Predicate.PROFILE_BINDING,
                Identifier(IdKind.PERSON_NAME, prof["name"]), purl,
                reliability=Reliability.MODERATE, correlation_group=group,
            ))
        if prof.get("email"):
            claims.append(self.claim(
                handle, Predicate.PROFILE_BINDING,
                Identifier(IdKind.EMAIL, prof["email"]), purl,
                reliability=Reliability.STRONG, correlation_group=group,
            ))
        if prof.get("company"):
            claims.append(self.claim(
                handle, Predicate.EMPLOYED_BY,
                Identifier(IdKind.ORG_NAME, prof["company"].lstrip("@")), purl,
                reliability=Reliability.WEAK, correlation_group=group,
            ))
        if prof.get("blog"):
            dom = re.sub(r"^https?://(www\.)?", "", prof["blog"]).split("/")[0].lower()
            if "." in dom:
                claims.append(self.claim(
                    handle, Predicate.OPERATES,
                    Identifier(IdKind.DOMAIN, dom), purl,
                    reliability=Reliability.MODERATE, correlation_group=group,
                ))

        # -- key material: high selectivity, cryptographically bound -------- #
        for path, kind, pred in (
            ("gpg_keys", IdKind.PGP_FPR, Predicate.KEY_BINDING),
            ("keys", IdKind.SSH_FPR, Predicate.KEY_BINDING),
        ):
            kurl = f"{self.API}/users/{login}/{path}"
            keys = await self.fetcher.get_json(kurl, headers=self._hdr()) or []
            for k in keys:
                fpr = k.get("key_id") or _ssh_fpr(k.get("key", ""))
                if not fpr:
                    continue
                claims.append(self.claim(
                    handle, pred, Identifier(kind, fpr), kurl,
                    reliability=Reliability.AUTHORITATIVE,
                    correlation_group=f"github_keys|{login}|{path}",
                ))
                for em in (k.get("emails") or []):
                    if em.get("verified") and em.get("email"):
                        claims.append(self.claim(
                            Identifier(kind, fpr), Predicate.KEY_BINDING,
                            Identifier(IdKind.EMAIL, em["email"]), kurl,
                            reliability=Reliability.AUTHORITATIVE,
                            correlation_group=f"github_keys|{login}|{path}",
                        ))

        # -- commit authorship + timezone inference ------------------------- #
        eurl = f"{self.API}/users/{login}/events/public?per_page=100"
        events = await self.fetcher.get_json(eurl, headers=self._hdr()) or []
        emails: set[str] = set()
        hours: Counter[int] = Counter()

        for ev in events:
            for c in (ev.get("payload", {}).get("commits") or []):
                em = (c.get("author") or {}).get("email")
                if em:
                    emails.add(em.lower())
            ts = ev.get("created_at")
            if ts:
                with contextlib.suppress(ValueError):
                    hours[datetime.fromisoformat(ts.replace("Z", "+00:00")).hour] += 1

        # One correlation group for ALL commit emails from this actor:
        # 100 events is one observation of one developer, not 100 observations.
        for em in emails:
            if em.endswith("users.noreply.github.com"):
                continue
            claims.append(self.claim(
                handle, Predicate.COMMIT_EMAIL,
                Identifier(IdKind.EMAIL, em), eurl,
                reliability=Reliability.STRONG,
                correlation_group=f"github_commits|{login}",
            ))

        if sum(hours.values()) >= 25:
            tz = _infer_timezone(hours)
            if tz is not None:
                claims.append(self.claim(
                    handle, Predicate.TIMEZONE_HINT, f"UTC{tz:+d}", eurl,
                    reliability=Reliability.WEAK,
                    correlation_group=f"github_tz|{login}",
                    raw={"histogram": dict(hours)},
                ))
        return claims


def _infer_timezone(hours: Counter[int]) -> int | None:
    """Infer UTC offset from a UTC activity histogram.

    Assumes the quietest contiguous 6h window is local 01:00-07:00. Crude, and
    weighted accordingly (Reliability.WEAK, and TIMEZONE_HINT is corroborative
    only in the scoring model -- it can never establish a link by itself).
    """
    if not hours:
        return None
    best_start, best_sum = None, None
    for start in range(24):
        window = sum(hours.get((start + i) % 24, 0) for i in range(6))
        if best_sum is None or window < best_sum:
            best_sum, best_start = window, start
    if best_start is None:
        return None
    offset = (1 - best_start) % 24
    return offset - 24 if offset > 12 else offset


def _ssh_fpr(key: str) -> str | None:
    import base64
    parts = key.split()
    if len(parts) < 2:
        return None
    try:
        blob = base64.b64decode(parts[1])
    except Exception:
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


# --------------------------------------------------------------------------- #
# Username expansion (WhatsMyName dataset)
# --------------------------------------------------------------------------- #

@register
class UsernameExpand(Collector):
    name = "username_expand"
    source_class = SourceClass.PLATFORM_PUBLIC_API
    accepts = (IdKind.HANDLE,)
    priority = 4

    WMN = (
        "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
    )
    #: Cap on sites probed per handle. Uncapped enumeration across 600 sites is
    #: a profile-building exercise, not an attribution step.
    MAX_SITES = 40

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        # Third key, specific to enumeration. Sweeping hundreds of sites for a
        # bare handle is a different operation from looking up an identifier you
        # already hold, so it takes its own switch.
        if not getattr(self.scope, "allow_username_enumeration", False):
            self.scope.audit(
                "enumeration_gated", collector=self.name, identifier=ident.key,
                reason="allow_username_enumeration is not set in the case file")
            return []

        username = ident.value.split(":", 1)[-1]
        if len(username) < 4:
            return []   # short handles collide across unrelated people

        data = await self.fetcher.get_json(self.WMN)
        sites = (data or {}).get("sites", [])[: self.MAX_SITES]

        claims: list[Claim] = []
        for site in sites:
            uri = site.get("uri_check", "").replace("{account}", username)
            if not uri:
                continue
            r = await self.fetcher.get(uri, allow_html=True)
            if not r:
                continue
            ok = (
                r.status == site.get("e_code")
                and site.get("e_string", "") in r.text
                and site.get("m_string", "\x00") not in r.text
            )
            if ok:
                claims.append(self.claim(
                    ident, Predicate.PROFILE_BINDING,
                    Identifier(IdKind.URL, uri), uri,
                    reliability=Reliability.WEAK,
                    # Handle reuse across N sites is ONE observation about one
                    # naming habit, not N independent observations.
                    correlation_group=f"handle_reuse|{username}",
                    raw={"site": site.get("name")},
                ))
        return claims


# --------------------------------------------------------------------------- #
# PGP keyservers (VKS)
# --------------------------------------------------------------------------- #

@register
class PgpKeyserver(Collector):
    name = "pgp_wkd"
    source_class = SourceClass.PUBLIC_PROTOCOL
    accepts = (IdKind.EMAIL, IdKind.PGP_FPR)
    priority = 3

    VKS = "https://keys.openpgp.org/vks/v1"

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        if ident.kind is IdKind.EMAIL:
            url = f"{self.VKS}/by-email/{ident.value}"
        else:
            url = f"{self.VKS}/by-fingerprint/{ident.value.upper().replace(':', '')}"
        r = await self.fetcher.get(url)
        if not r or r.status != 200 or "BEGIN PGP PUBLIC KEY" not in r.text:
            return []

        claims: list[Claim] = []
        group = f"pgp|{ident.value}"
        try:
            import pgpy  # optional dependency
            key, _ = pgpy.PGPKey.from_blob(r.text)
            fpr = Identifier(IdKind.PGP_FPR, str(key.fingerprint).replace(" ", ""))
            for uid in key.userids:
                if uid.email:
                    claims.append(self.claim(
                        fpr, Predicate.KEY_BINDING,
                        Identifier(IdKind.EMAIL, uid.email), url,
                        reliability=Reliability.STRONG, correlation_group=group,
                    ))
                if uid.name:
                    claims.append(self.claim(
                        fpr, Predicate.KEY_BINDING,
                        Identifier(IdKind.PERSON_NAME, uid.name), url,
                        reliability=Reliability.MODERATE, correlation_group=group,
                    ))
        except ImportError:
            claims.append(self.claim(
                ident, Predicate.KEY_BINDING, "pgp_key_present", url,
                reliability=Reliability.MODERATE, correlation_group=group,
            ))
        return claims


# --------------------------------------------------------------------------- #
# holehe wrapper (subprocess)
# --------------------------------------------------------------------------- #

@register
class Holehe(Collector):
    name = "holehe"
    source_class = SourceClass.PLATFORM_PUBLIC_API
    accepts = (IdKind.EMAIL,)
    priority = 4

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        import asyncio
        import shutil

        if not shutil.which("holehe"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "holehe", ident.value, "--only-used", "--no-color", "--no-clear",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        claims: list[Claim] = []
        for line in out.decode(errors="ignore").splitlines():
            m = re.match(r"^\s*\[\+\]\s+(\S+)", line)
            if m:
                claims.append(self.claim(
                    ident, Predicate.PROFILE_BINDING,
                    Identifier(IdKind.URL, f"account_on:{m.group(1)}"), "holehe://local",
                    reliability=Reliability.WEAK,
                    # Account existence across N services is one observation of
                    # one email's registration history.
                    correlation_group=f"holehe|{ident.value}",
                ))
        return claims
