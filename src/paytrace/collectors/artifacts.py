"""Deep artifact extraction from a domain's own surface.

The seed rarely names its operator. A sibling — a domain sharing a hosting IP, an
analytics ID, a seller account — often does, because operators are consistent on
one property and careless on another. So every identifier pulled here is a
*pivot*: fed back to the frontier, it re-runs collection on whatever it reaches,
and the answer that was absent on the seed appears three domains over.

This module extracts what a page reveals about who made it:

    HTML comments        build tools, developer notes, staging URLs, names
    <meta> author        CMS-populated author fields
    WordPress users      /wp-json/wp/v2/users enumerates display names + slugs
    Gravatar hashes      md5 of an email -> the email's owner elsewhere
    service IDs          analytics, tag managers, CRM, support widgets
    Google Docs links    published doc/sheet IDs, often with an owner
    OAuth client emails   google-signin client_id -> project, sometimes email
    WebFinger            /.well-known/webfinger -> account handles
    body emails/URLs     addresses and links in rendered text
    response headers     X-Powered-By, Server, framework fingerprints

And what a misconfigured server exposes without meaning to:

    /.env                credentials, SMTP users, API keys, DB names
    /.git/config         remote URL -> the operator's GitHub/GitLab account
    /config, /backup     stray files a directory listing reveals

## Exposed files are handled, never harvested

An exposed ``/.env`` may contain live credentials. This module records **that it
was exposed** and extracts only non-secret identifiers from it — an SMTP
username that is an email, a remote git URL, a project name. It does not store
secret values, and the evidence note flags the exposure so it can be reported to
the operator rather than used against them. A tool that hoovers up leaked
secrets is a breach, not an investigation.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from attribution_graph import (
    Claim,
    Identifier,
    IdKind,
    Predicate,
    Reliability,
    SourceClass,
)

from ..fingerprint import gravatar_hash  # re-exported; canonical home is fingerprint.py
from ..sellersjson import SellerNameKind, classify_seller_name
from .base import Collector, register
from .disclosure import extract_store_identifiers

# --------------------------------------------------------------------------- #
# Extraction patterns
# --------------------------------------------------------------------------- #

_EMAIL = re.compile(r"[\w.+\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,4}")
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_META_AUTHOR = re.compile(
    r'<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']{2,80})', re.I)
_GRAVATAR = re.compile(
    r"(?:gravatar\.com/avatar/|secure\.gravatar\.com/avatar/)([a-f0-9]{32})", re.I)
_GDOC = re.compile(
    r"docs\.google\.com/(?:document|spreadsheets|presentation)/d/([\w\-]{20,60})", re.I)
_GDRIVE = re.compile(r"drive\.google\.com/file/d/([\w\-]{20,60})", re.I)
_OAUTH_CLIENT = re.compile(
    r"([\w\-]{12,}\.apps\.googleusercontent\.com)", re.I)
_STAGING = re.compile(
    r"\b((?:staging|dev|test|beta|old|www2|admin|cpanel)\.[\w\-.]+\.[a-z]{2,})\b", re.I)

#: Service identifier schemes worth extracting from source. Each is a pivot.
_SERVICE_IDS = {
    # Digits only, matching analytics.py: the `pub-` prefix is spelling, not
    # identity. Keeping it here made one payee two nodes.
    "adsense": re.compile(r"\b(?:ca-)?pub-(\d{16})\b"),
    "ga4": re.compile(r"\b(G-[A-Z0-9]{8,12})\b"),
    # The ACCOUNT part only, matching analytics.py. UA-1234-1 and UA-1234-2 are
    # two properties of one account; keeping the suffix split them.
    "ua": re.compile(r"\b(UA-\d{4,10})-\d{1,4}\b"),
    "gtm": re.compile(r"\b(GTM-[A-Z0-9]{5,9})\b"),
    "fbpixel": re.compile(r"fbq\(['\"]init['\"],\s*['\"](\d{15,16})['\"]"),
    "hotjar": re.compile(r"hjid[:=]\s*(\d{6,8})"),
    "intercom": re.compile(r"app_id[\"']?\s*[:=]\s*[\"']([a-z0-9]{8})[\"']"),
    "sentry": re.compile(r"https://([a-f0-9]{32})@[\w.]+\.ingest\.sentry\.io"),
    "mixpanel": re.compile(r"mixpanel\.init\(['\"]([a-f0-9]{32})['\"]"),
    "hubspot": re.compile(r"js\.hs-scripts\.com/(\d{5,10})\.js"),
    "yandex": re.compile(r"ym\((\d{6,9}),"),
    "clarity": re.compile(r"clarity[\"']?\s*,\s*[\"']([a-z0-9]{10})[\"']"),
}

#: Framework and stack fingerprints from response headers.
_HEADER_SIGNALS = ("x-powered-by", "server", "x-generator", "x-drupal-cache",
                   "x-pingback", "x-shopify-stage", "x-wix-request-id")


@dataclass
class Artifacts:
    emails: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    gravatars: set[str] = field(default_factory=set)
    service_ids: dict[str, set[str]] = field(default_factory=dict)
    gdocs: set[str] = field(default_factory=set)
    oauth_clients: set[str] = field(default_factory=set)
    subdomains: set[str] = field(default_factory=set)
    comments: list[str] = field(default_factory=list)
    exposures: list[tuple[str, str]] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Collector
# --------------------------------------------------------------------------- #

@register
class DeepArtifacts(Collector):
    """Everything a domain's own surface reveals about who built it.

    The highest-value collector for the sibling-pivot pattern: it runs on the
    seed and on every domain the frontier reaches, and each identifier it finds
    is a new pivot. An email absent from the seed frequently sits in a WordPress
    user list or an exposed git config on a domain two hops away.
    """

    name = "deep_artifacts"
    source_class = SourceClass.SELF_PUBLISHED
    accepts = (IdKind.DOMAIN,)
    priority = 1

    #: Files an operator sometimes exposes by accident. Presence is recorded;
    #: secret values are never stored.
    PROBE_PATHS = (
        "/wp-json/wp/v2/users", "/.well-known/webfinger",
        "/.env", "/.git/config", "/humans.txt", "/security.txt",
        "/.well-known/security.txt",
    )

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        domain = ident.value
        claims: list[Claim] = []

        home = await self.fetcher.get(f"https://{domain}/", allow_html=True)
        if home and home.status == 200 and home.text:
            arts = self._extract_source(home.text)
            claims += self._emit(ident, arts, f"https://{domain}/")
            claims += self._headers(ident, home)

        for path in self.PROBE_PATHS:
            claims += await self._probe(ident, domain, path)

        return claims

    # -- page source -------------------------------------------------------- #

    def _extract_source(self, html: str) -> Artifacts:
        a = Artifacts()

        for m in _HTML_COMMENT.findall(html):
            c = m.strip()
            if c and len(c) < 400 and not c.startswith(("[if", "google", "/")):
                a.comments.append(c)
                # names and emails hide in developer comments
                a.emails.update(_EMAIL.findall(c))

        for m in _META_AUTHOR.findall(html):
            a.names.add(m.strip())

        a.gravatars.update(_GRAVATAR.findall(html))
        a.gdocs.update(_GDOC.findall(html))
        a.gdocs.update(_GDRIVE.findall(html))
        a.oauth_clients.update(_OAUTH_CLIENT.findall(html))
        a.subdomains.update(s.lower() for s in _STAGING.findall(html))

        for scheme, pattern in _SERVICE_IDS.items():
            found = set(pattern.findall(html))
            if found:
                a.service_ids.setdefault(scheme, set()).update(found)

        # Body emails, minus the analytics/asset noise.
        for em in _EMAIL.findall(re.sub(r"<[^>]+>", " ", html)):
            low = em.lower()
            if not low.endswith((".png", ".jpg", ".gif", ".svg", ".webp",
                                 ".css", ".js", "example.com", "sentry.io",
                                 "wixpress.com", "@2x")):
                a.emails.add(low)
        return a

    def _emit(self, ident, a: Artifacts, url: str) -> list[Claim]:
        out: list[Claim] = []
        D = ident.value

        for em in a.emails:
            out.append(self.claim(
                ident, Predicate.PROFILE_BINDING, Identifier(IdKind.EMAIL, em),
                url, reliability=Reliability.MODERATE,
                correlation_group=f"artifacts|{D}|email",
                raw={"artifact": "page source"}))

        for name in a.names:
            kind = (IdKind.PERSON_NAME
                    if classify_seller_name(name) is SellerNameKind.NATURAL_PERSON
                    else IdKind.ORG_NAME)
            out.append(self.claim(
                ident, Predicate.REGISTRANT, Identifier(kind, name), url,
                reliability=Reliability.WEAK,
                correlation_group=f"artifacts|{D}|author",
                raw={"artifact": "meta author"}))

        for h in a.gravatars:
            # A Gravatar hash is md5 of an email. It links this page to the same
            # email anywhere else the hash appears, without revealing the email.
            out.append(self.claim(
                ident, Predicate.PROFILE_BINDING,
                Identifier(IdKind.GRAVATAR_HASH, h), url,
                reliability=Reliability.STRONG,
                correlation_group=f"artifacts|{D}|gravatar",
                raw={"artifact": "gravatar hash",
                     "pivot": "matches any profile using the same email"}))

        for scheme, ids in a.service_ids.items():
            for sid in ids:
                out.append(self.claim(
                    ident, Predicate.SHARES_ANALYTICS_ID,
                    Identifier(IdKind.ANALYTICS_ID, f"{scheme}:{sid}"), url,
                    reliability=Reliability.AUTHORITATIVE,
                    correlation_group=f"artifacts|{D}|{scheme}",
                    raw={"artifact": "service id",
                         "pivot": "reverse-lookup finds co-owned domains"}))

        for doc in a.gdocs:
            out.append(self.claim(
                ident, Predicate.PROFILE_BINDING,
                Identifier(IdKind.URL, f"gdoc:{doc}"), url,
                reliability=Reliability.MODERATE,
                correlation_group=f"artifacts|{D}|gdoc",
                raw={"artifact": "google doc/drive link",
                     "pivot": "published docs sometimes expose an owner"}))

        for client in a.oauth_clients:
            out.append(self.claim(
                ident, Predicate.OPERATES,
                Identifier(IdKind.URL, f"oauth:{client}"), url,
                reliability=Reliability.MODERATE,
                correlation_group=f"artifacts|{D}|oauth",
                raw={"artifact": "google oauth client",
                     "pivot": "client_id ties to a Google Cloud project"}))

        for sub in a.subdomains:
            out.append(self.claim(
                ident, Predicate.OPERATES, Identifier(IdKind.DOMAIN, sub), url,
                reliability=Reliability.WEAK,
                correlation_group=f"artifacts|{D}|subdomain",
                raw={"artifact": "staging/admin subdomain in source",
                     "pivot": "staging hosts are often less locked down"}))

        # Store links: a mandated-disclosure pointer (see disclosure.py).
        for sid in extract_store_identifiers("".join(a.comments) + url):
            out.append(self.claim(
                ident, Predicate.OPERATES, Identifier(IdKind.URL, sid), url,
                reliability=Reliability.STRONG,
                correlation_group=f"artifacts|{D}|store"))
        return out

    # -- headers ------------------------------------------------------------ #

    def _headers(self, ident, response) -> list[Claim]:
        headers = getattr(response, "headers", {}) or {}
        out: list[Claim] = []
        for key in _HEADER_SIGNALS:
            val = headers.get(key) or headers.get(key.title())
            if val:
                out.append(self.claim(
                    ident, Predicate.PROFILE_BINDING,
                    Identifier(IdKind.URL, f"header:{key}={val}"[:120]),
                    f"https://{ident.value}/", reliability=Reliability.WEAK,
                    correlation_group=f"artifacts|{ident.value}|headers",
                    raw={"artifact": "response header", "header": key}))
        return out

    # -- probed paths ------------------------------------------------------- #

    async def _probe(self, ident, domain: str, path: str) -> list[Claim]:
        url = f"https://{domain}{path}"
        r = await self.fetcher.get(url, allow_html=True)
        if not r or r.status != 200 or not r.text:
            return []

        if path.endswith("/users"):
            return self._wordpress_users(ident, r.text, url)
        if "webfinger" in path:
            return self._webfinger(ident, r.text, url)
        if path == "/.env":
            return self._dotenv(ident, r.text, url)
        if path.endswith("/config") and ".git" in path:
            return self._git_config(ident, r.text, url)
        if path in ("/humans.txt", "/security.txt",
                    "/.well-known/security.txt"):
            return self._text_contacts(ident, r.text, url, path)
        return []

    def _wordpress_users(self, ident, body: str, url: str) -> list[Claim]:
        """WP REST API enumerates display names and slugs by default."""
        try:
            users = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: list[Claim] = []
        for u in users if isinstance(users, list) else []:
            name, slug = u.get("name"), u.get("slug")
            if name:
                kind = (IdKind.PERSON_NAME
                        if classify_seller_name(name) is SellerNameKind.NATURAL_PERSON
                        else IdKind.ORG_NAME)
                out.append(self.claim(
                    ident, Predicate.REGISTRANT, Identifier(kind, name), url,
                    reliability=Reliability.MODERATE,
                    correlation_group=f"wp_users|{ident.value}",
                    raw={"artifact": "WordPress user", "slug": slug}))
            if slug and slug != (name or "").lower().replace(" ", ""):
                out.append(self.claim(
                    ident, Predicate.PROFILE_BINDING,
                    Identifier(IdKind.HANDLE, f"wp:{slug}"), url,
                    reliability=Reliability.WEAK,
                    correlation_group=f"wp_users|{ident.value}",
                    raw={"artifact": "WordPress author slug",
                         "pivot": "author slugs often reused as usernames"}))
        return out

    def _webfinger(self, ident, body: str, url: str) -> list[Claim]:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: list[Claim] = []
        subject = data.get("subject", "")
        if subject.startswith("acct:"):
            out.append(self.claim(
                ident, Predicate.PROFILE_BINDING,
                Identifier(IdKind.HANDLE, subject[5:]), url,
                reliability=Reliability.MODERATE,
                correlation_group=f"webfinger|{ident.value}",
                raw={"artifact": "WebFinger subject"}))
        return out

    def _dotenv(self, ident, body: str, url: str) -> list[Claim]:
        """An exposed .env. Record the exposure; extract only non-secrets.

        Secret values are never stored. What is useful and not secret: an SMTP
        or mail-from address (an email), an app name, a public database host.
        """
        out: list[Claim] = [self.claim(
            ident, Predicate.OPERATES,
            Identifier(IdKind.URL, f"exposure:{ident.value}/.env"), url,
            reliability=Reliability.STRONG, weight=0.0,
            correlation_group=f"exposure|{ident.value}",
            raw={"artifact": "EXPOSED .env FILE",
                 "severity": "the operator is leaking configuration; report it",
                 "note": "secret values deliberately not extracted or stored"})]

        for line in body.splitlines():
            if "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip().upper()
            v = v.strip().strip('"\'')
            # Emails are identifiers, not secrets.
            if _EMAIL.fullmatch(v) and any(
                    t in k for t in ("MAIL", "SMTP", "FROM", "ADMIN", "USER")):
                out.append(self.claim(
                    ident, Predicate.PROFILE_BINDING,
                    Identifier(IdKind.EMAIL, v.lower()), url,
                    reliability=Reliability.STRONG,
                    correlation_group=f"exposure|{ident.value}|email",
                    raw={"artifact": "email in exposed .env", "key": k}))
            elif k in ("APP_NAME", "MAIL_FROM_NAME") and 2 < len(v) < 60:
                kind = (IdKind.PERSON_NAME
                        if classify_seller_name(v) is SellerNameKind.NATURAL_PERSON
                        else IdKind.ORG_NAME)
                out.append(self.claim(
                    ident, Predicate.REGISTRANT, Identifier(kind, v), url,
                    reliability=Reliability.WEAK,
                    correlation_group=f"exposure|{ident.value}|name",
                    raw={"artifact": "app name in exposed .env"}))
        return out

    def _git_config(self, ident, body: str, url: str) -> list[Claim]:
        """An exposed .git/config. The remote URL names the operator's repo."""
        out: list[Claim] = [self.claim(
            ident, Predicate.OPERATES,
            Identifier(IdKind.URL, f"exposure:{ident.value}/.git/config"), url,
            reliability=Reliability.STRONG, weight=0.0,
            correlation_group=f"exposure|{ident.value}",
            raw={"artifact": "EXPOSED .git/config",
                 "severity": "source-control config is public; report it"})]

        for m in re.finditer(r"url\s*=\s*(\S+)", body):
            remote = m.group(1)
            gh = re.search(r"github\.com[:/]([\w\-]+)/([\w\-.]+?)(?:\.git)?$", remote)
            gl = re.search(r"gitlab\.com[:/]([\w\-]+)/", remote)
            owner = (gh.group(1) if gh else gl.group(1) if gl else None)
            if owner:
                out.append(self.claim(
                    ident, Predicate.OPERATES,
                    Identifier(IdKind.HANDLE, f"github:{owner}"
                               if gh else f"gitlab:{owner}"), url,
                    reliability=Reliability.STRONG,
                    correlation_group=f"git_remote|{ident.value}",
                    raw={"artifact": "git remote in exposed config",
                         "pivot": "code-host account ties to a real developer"}))
            for em in _EMAIL.findall(body):
                out.append(self.claim(
                    ident, Predicate.PROFILE_BINDING,
                    Identifier(IdKind.EMAIL, em.lower()), url,
                    reliability=Reliability.MODERATE,
                    correlation_group=f"git_remote|{ident.value}",
                    raw={"artifact": "committer email in exposed git config"}))
        return out

    def _text_contacts(self, ident, body: str, url: str, path: str) -> list[Claim]:
        """humans.txt and security.txt frequently name a person or contact."""
        out: list[Claim] = []
        for em in dict.fromkeys(_EMAIL.findall(body)):
            out.append(self.claim(
                ident, Predicate.PROFILE_BINDING,
                Identifier(IdKind.EMAIL, em.lower()), url,
                reliability=Reliability.MODERATE,
                correlation_group=f"contacts|{ident.value}|{path}",
                raw={"artifact": path.lstrip("/.")}))
        return out


# --------------------------------------------------------------------------- #
# Gravatar hash resolution
# --------------------------------------------------------------------------- #

# Re-exported from fingerprint.py, the canonical home. A second implementation
# here would drift, as name variation and handle generation already did.

__all__ = ["DeepArtifacts", "gravatar_hash"]
