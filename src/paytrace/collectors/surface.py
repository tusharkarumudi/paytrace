"""Web surface harvesting.

The pivot this completes. A seed domain is chosen by the investigator and often
holds nothing — a privacy-proxied registrant, a Gmail contact, no name. But the
seed shares a hosting IP or an analytics ID with three other domains, and *those*
are where the operator was careless: a WordPress author endpoint exposing a
username, a leaked ``.env``, a real name in an HTML comment, an OAuth email in a
login redirect.

The frontier already re-collects discovered domains within ``pivot_radius``.
What it lacked was a collector that mines a domain's *surface* rather than its
registries. This is that collector, and it is the single highest-yield addition
for anonymous-operator cases, because operators harden the property they expect
to be examined and neglect the ones they forgot they own.

## What it looks for, and why each matters

| Signal | Why it identifies |
|---|---|
| Author names in body / meta / comments | The operator wrote the copy and signed it once |
| WordPress ``?author=N`` and REST ``/wp-json/wp/v2/users`` | WP leaks the login slug by design |
| ``mailto:`` and body emails | An OAuth or support address the registrant hid |
| Gravatar hashes | An email's MD5, which reverses to the address in a breach corpus |
| Google Docs / Drive links | Frequently owned by a named account |
| Exposed ``.env`` / ``.git/config`` | Real names, keys, remote URLs — the jackpot |
| WebFinger ``/.well-known/webfinger`` | Federated identity, maps a handle to an account |
| Service IDs (Disqus, Intercom, Crisp, Sentry) | Shared across an operator's whole estate |
| HTTP headers (``Server``, ``X-Powered-By``) | Stack fingerprint that clusters a portfolio |

## Safety

Everything here is a **GET of a path the server chose to expose**. This does not
probe for vulnerabilities, brute-force paths, or authenticate. A ``.env`` that
returns 200 was published by the operator's misconfiguration; retrieving it is
reading a public URL, and the collector records that it did so in the evidence
manifest. The line it will not cross is enumeration: it fetches a fixed, small
set of conventional paths, never a generated wordlist.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from attribution_graph import (
    Claim,
    Identifier,
    IdKind,
    Predicate,
    Reliability,
    SourceClass,
)

from .base import Collector, register
from .disclosure import extract_store_identifiers

# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #

_EMAIL = re.compile(r"[\w.+\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,4}")
_MAILTO = re.compile(r"mailto:([\w.+\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,4})", re.I)
_GRAVATAR = re.compile(
    r"(?:gravatar\.com/avatar/|secure\.gravatar\.com/avatar/)([0-9a-f]{32})", re.I)
_GDOC = re.compile(
    r"docs\.google\.com/(?:document|spreadsheets|presentation)"
    r"/d/([\w\-]{20,})", re.I)
_GDRIVE = re.compile(r"drive\.google\.com/(?:file/d/|open\?id=)([\w\-]{20,})", re.I)
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_WP_AUTHOR = re.compile(r'/author/([a-z0-9][\w\-]{1,30})/', re.I)
_META_AUTHOR = re.compile(
    r'<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']{2,80})["\']', re.I)
_GENERATOR = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{2,80})["\']', re.I)
_BYLINE = re.compile(
    r'(?:written|posted|authored|created)\s+by[:\s]+([A-Z][\w.\'\-]+(?:\s+[A-Z][\w.\'\-]+){0,3})',
    re.I)

#: Third-party service IDs that recur across an operator's properties.
_SERVICE_IDS = {
    "disqus": re.compile(r'["\']?([\w\-]+)\.disqus\.com', re.I),
    "intercom": re.compile(r'app_id["\']?\s*[:=]\s*["\']([\w]{6,12})["\']', re.I),
    "crisp": re.compile(r'CRISP_WEBSITE_ID\s*=\s*["\']([\w\-]{20,})["\']', re.I),
    "sentry": re.compile(r'https://[\w]+@([\w.]+)\.ingest\.sentry\.io/(\d+)', re.I),
    "hotjar": re.compile(r'hjid["\']?\s*[:=]\s*["\']?(\d{6,9})', re.I),
    "mixpanel": re.compile(r'mixpanel\.init\(["\']([\w]{20,})["\']', re.I),
}

#: Header names whose values cluster a stack. Case-insensitive on the wire.
_FINGERPRINT_HEADERS = (
    "server", "x-powered-by", "x-generator", "x-drupal-cache", "x-pingback",
    "x-served-by", "cf-ray", "x-github-request-id",
)

#: Names that are never a person's byline.
_NAME_STOPWORDS = frozenset({
    "admin", "administrator", "editor", "author", "user", "webmaster", "root",
    "guest", "test", "demo", "support", "team", "staff", "the", "wordpress",
})

#: Conventional paths the server may have left exposed. A fixed, small set --
#: never a generated list. Each is a real misconfiguration seen in the wild.
_EXPOSED_PATHS = (
    (".env", "env_leak"),
    (".git/config", "git_config"),
    ("wp-json/wp/v2/users", "wp_users"),
    (".well-known/webfinger", "webfinger"),
    (".well-known/security.txt", "security_txt"),
    ("humans.txt", "humans_txt"),
    ("phpinfo.php", "phpinfo"),
    ("config.json", "config_leak"),
    ("backup.sql", "sql_backup"),
)

_ENV_KEY = re.compile(r"^([A-Z][A-Z0-9_]{2,40})\s*=\s*(.+)$", re.M)
_GIT_URL = re.compile(r"url\s*=\s*(\S+)", re.I)
_WP_USER_JSON = re.compile(r'"slug"\s*:\s*"([\w\-]+)"')
_WP_USER_NAME = re.compile(r'"name"\s*:\s*"([^"]{2,80})"')


# --------------------------------------------------------------------------- #
# Collector
# --------------------------------------------------------------------------- #

@register
class SurfaceHarvest(Collector):
    """Mine a domain's public surface for identity leads.

    Runs on every domain the frontier reaches, not just the seed. That is the
    point: the seed is chosen for being investigable, and the answer is usually
    on a sibling the operator forgot to harden.
    """

    name = "surface_harvest"
    source_class = SourceClass.SELF_PUBLISHED
    accepts = (IdKind.DOMAIN,)
    priority = 2

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        domain = ident.value
        home = f"https://{domain}/"
        claims: list[Claim] = []

        r = await self.fetcher.get(home, allow_html=True)
        if r and r.status == 200 and r.text:
            claims.extend(self._harvest_html(ident, home, r.text))
            claims.extend(self._harvest_headers(ident, home, getattr(r, "headers", {})))

        claims.extend(await self._harvest_exposed_paths(ident, domain))
        return claims

    # -- HTML body ----------------------------------------------------------- #

    def _harvest_html(self, ident: Identifier, url: str, html: str) -> list[Claim]:
        out: list[Claim] = []
        group = f"surface|{ident.value}"

        def add(pred, obj_kind, value, *, rel=Reliability.WEAK, **raw):
            out.append(self.claim(
                ident, pred, Identifier(obj_kind, value), url,
                reliability=rel, correlation_group=group, raw=raw))

        # Emails: mailto is stronger than a bare body match.
        for em in dict.fromkeys(_MAILTO.findall(html)):
            add(Predicate.PROFILE_BINDING, IdKind.EMAIL, em.lower(),
                rel=Reliability.MODERATE, source="mailto")
        body_emails = set(_EMAIL.findall(_HTML_COMMENT.sub(" ", html)))
        for em in list(body_emails - set(_MAILTO.findall(html)))[:8]:
            low = em.lower()
            if low.endswith(("example.com", "sentry.io", "w3.org", "wordpress.org")):
                continue
            add(Predicate.PROFILE_BINDING, IdKind.EMAIL, low, source="body")

        # Emails hidden in HTML comments are almost always developer leftovers.
        for comment in _HTML_COMMENT.findall(html):
            for em in dict.fromkeys(_EMAIL.findall(comment)):
                add(Predicate.PROFILE_BINDING, IdKind.EMAIL, em.lower(),
                    rel=Reliability.MODERATE, source="html_comment",
                    note="email in an HTML comment — developer leftover")
            for m in _BYLINE.finditer(comment):
                self._maybe_name(add, m.group(1), "html_comment")

        # Author signals.
        for m in _META_AUTHOR.finditer(html):
            self._maybe_name(add, m.group(1), "meta_author",
                             rel=Reliability.MODERATE)
        for m in _BYLINE.finditer(html):
            self._maybe_name(add, m.group(1), "byline")

        # WordPress author slugs leak the login name.
        for slug in dict.fromkeys(_WP_AUTHOR.findall(html)):
            if slug.lower() not in _NAME_STOPWORDS:
                add(Predicate.PROFILE_BINDING, IdKind.HANDLE, f"wp:{slug}",
                    rel=Reliability.MODERATE, source="wp_author_url",
                    note="WordPress author slug — the account login name")

        # Gravatar hashes reverse to an email in a breach corpus.
        for h in dict.fromkeys(_GRAVATAR.findall(html)):
            add(Predicate.PROFILE_BINDING, IdKind.GRAVATAR_HASH, h.lower(),
                rel=Reliability.MODERATE, source="gravatar")

        # Google Docs / Drive frequently owned by a named account.
        for doc_id in dict.fromkeys(_GDOC.findall(html) + _GDRIVE.findall(html)):
            add(Predicate.PROFILE_BINDING, IdKind.URL, f"gdoc:{doc_id}",
                source="google_docs",
                note="Google document — ownership often resolves to a name")

        # Service IDs cluster the estate.
        for service, pat in _SERVICE_IDS.items():
            for m in pat.finditer(html):
                sid = m.group(1)
                add(Predicate.SHARES_ANALYTICS_ID, IdKind.SERVICE_ID,
                    f"{service}:{sid}", rel=Reliability.STRONG,
                    source=f"service_{service}",
                    note=f"{service} ID — shared across an operator's properties")

        # Generator string (stack fingerprint, weak clustering signal).
        for m in _GENERATOR.finditer(html):
            add(Predicate.CO_HOSTED, IdKind.URL, f"generator:{m.group(1)[:60]}",
                source="meta_generator", weight=0.0)

        # Store links (mandated disclosure pivots) on any discovered domain too.
        for sid in extract_store_identifiers(html):
            add(Predicate.OPERATES, IdKind.URL, sid, rel=Reliability.STRONG,
                source="store_link")

        return out

    def _maybe_name(self, add, raw_name: str, source: str,
                    rel=Reliability.WEAK) -> None:
        name = " ".join(raw_name.split())
        tokens = name.split()
        if not (2 <= len(tokens) <= 4):
            return
        if any(t.lower() in _NAME_STOPWORDS for t in tokens):
            return
        add(Predicate.REGISTRANT, IdKind.PERSON_NAME, name,
            rel=rel, source=source)

    # -- headers ------------------------------------------------------------- #

    def _harvest_headers(self, ident: Identifier, url: str, headers) -> list[Claim]:
        if not headers:
            return []
        lower = {str(k).lower(): str(v) for k, v in dict(headers).items()}
        out: list[Claim] = []
        parts = [f"{h}={lower[h]}" for h in _FINGERPRINT_HEADERS if h in lower]
        if parts:
            fp = hashlib.sha256(" ".join(sorted(parts)).encode()).hexdigest()[:16]
            out.append(self.claim(
                ident, Predicate.CO_HOSTED, Identifier(IdKind.URL, f"stackfp:{fp}"),
                url, reliability=Reliability.WEAK,
                correlation_group=f"surface|{ident.value}",
                raw={"source": "http_headers", "fingerprint_of": parts,
                     "note": "stack fingerprint — clusters a portfolio, does "
                             "not identify an operator on its own"}))
        return out

    # -- exposed paths ------------------------------------------------------- #

    async def _harvest_exposed_paths(self, ident: Identifier,
                                     domain: str) -> list[Claim]:
        out: list[Claim] = []
        group = f"surface_leak|{ident.value}"

        for path, kind in _EXPOSED_PATHS:
            url = f"https://{domain}/{path}"
            r = await self.fetcher.get(url, allow_html=True)
            if not r or r.status != 200 or not r.text:
                continue
            body = r.text

            if kind == "env_leak" and _ENV_KEY.search(body):
                out.extend(self._parse_env(ident, url, body, group))
            elif kind == "git_config" and "[core]" in body:
                out.extend(self._parse_git(ident, url, body, group))
            elif kind == "wp_users":
                out.extend(self._parse_wp_users(ident, url, body, group))
            elif kind == "webfinger":
                out.extend(self._parse_webfinger(ident, url, body, group))
            elif kind in ("humans_txt", "security_txt"):
                for em in list(dict.fromkeys(_EMAIL.findall(body)))[:5]:
                    out.append(self.claim(
                        ident, Predicate.PROFILE_BINDING,
                        Identifier(IdKind.EMAIL, em.lower()), url,
                        reliability=Reliability.MODERATE, correlation_group=group,
                        raw={"source": kind}))
                for m in _BYLINE.finditer(body):
                    self._maybe_name(
                        self._appender(out, ident, url, group,
                                       Reliability.WEAK, kind),
                        m.group(1), kind)
        return out

    def _appender(self, out, ident, url, group, rel, source, extra=None):
        """Build a claim-appending callback that binds its loop variables.

        The inline lambdas that did this captured ``url`` and ``key`` by
        reference, so every closure saw the last loop value -- a real bug ruff
        flagged (B023). Binding them here as arguments fixes it.
        """
        def add(pred, kind, value, **raw):
            out.append(self.claim(
                ident, pred, Identifier(kind, value), url,
                reliability=rel, correlation_group=group,
                raw={**raw, "source": source, **(extra or {})}))
        return add

    def _parse_env(self, ident, url, body, group) -> list[Claim]:
        """A published .env. Real names, emails, and keys — the jackpot."""
        out: list[Claim] = []
        interesting = {"MAIL_FROM_ADDRESS", "MAIL_USERNAME", "ADMIN_EMAIL",
                       "APP_NAME", "MAIL_FROM_NAME", "DB_USERNAME",
                       "AWS_ACCESS_KEY_ID", "GOOGLE_CLIENT_ID"}
        for key, value in _ENV_KEY.findall(body):
            value = value.strip().strip('"\'')
            if key not in interesting or not value:
                continue
            if "EMAIL" in key or "MAIL_FROM_ADDRESS" in key or "USERNAME" in key:
                for em in _EMAIL.findall(value):
                    out.append(self.claim(
                        ident, Predicate.REGISTRANT,
                        Identifier(IdKind.EMAIL, em.lower()), url,
                        reliability=Reliability.STRONG, correlation_group=group,
                        raw={"source": "env_leak", "key": key,
                             "note": "exposed .env file — operator "
                                     "misconfiguration, retrieved as published"}))
            elif key in ("APP_NAME", "MAIL_FROM_NAME"):
                self._maybe_name(
                    self._appender(out, ident, url, group, Reliability.MODERATE,
                                   "env_leak", extra={"key": key}),
                    value, "env_leak", rel=Reliability.MODERATE)
        # A key is never stored as a value; record only that credentials leaked.
        if any(k in body for k in ("AWS_ACCESS_KEY", "SECRET", "_TOKEN")):
            out.append(self.claim(
                ident, Predicate.PROFILE_BINDING,
                Identifier(IdKind.URL, f"leak:env/{ident.value}"), url,
                reliability=Reliability.STRONG, correlation_group=group,
                raw={"source": "env_leak", "severity": "credentials present",
                     "note": "secrets present but not recorded; flagged only"}))
        return out

    def _parse_git(self, ident, url, body, group) -> list[Claim]:
        out: list[Claim] = []
        for remote in dict.fromkeys(_GIT_URL.findall(body)):
            m = re.search(r"[:/]([\w\-]+)/([\w\-.]+?)(?:\.git)?$", remote)
            if m:
                out.append(self.claim(
                    ident, Predicate.OPERATES,
                    Identifier(IdKind.HANDLE, f"git:{m.group(1)}"), url,
                    reliability=Reliability.STRONG, correlation_group=group,
                    raw={"source": "git_config", "remote": remote,
                         "note": "exposed .git/config — remote reveals the "
                                 "account and repository"}))
        return out

    def _parse_wp_users(self, ident, url, body, group) -> list[Claim]:
        out: list[Claim] = []
        for slug in dict.fromkeys(_WP_USER_JSON.findall(body)):
            if slug.lower() in _NAME_STOPWORDS:
                continue
            out.append(self.claim(
                ident, Predicate.PROFILE_BINDING,
                Identifier(IdKind.HANDLE, f"wp:{slug}"), url,
                reliability=Reliability.STRONG, correlation_group=group,
                raw={"source": "wp_rest_users",
                     "note": "WordPress REST users endpoint — login name"}))
        for name in dict.fromkeys(_WP_USER_NAME.findall(body)):
            self._maybe_name(
                self._appender(out, ident, url, group, Reliability.MODERATE,
                               "wp_rest_users"),
                name, "wp_rest_users", rel=Reliability.MODERATE)
        return out

    def _parse_webfinger(self, ident, url, body, group) -> list[Claim]:
        out: list[Claim] = []
        for em in list(dict.fromkeys(_EMAIL.findall(body)))[:3]:
            out.append(self.claim(
                ident, Predicate.PROFILE_BINDING,
                Identifier(IdKind.EMAIL, em.lower()), url,
                reliability=Reliability.MODERATE, correlation_group=group,
                raw={"source": "webfinger",
                     "note": "WebFinger subject — federated identity"}))
        return out
