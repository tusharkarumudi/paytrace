"""Deep artifact extraction from a page body.

The seed domain is frequently a dead end — a clean marketing page behind
Cloudflare, giving up nothing. The answer lives on a sibling: another property
by the same operator, found through a shared analytics ID or hosting IP, that
was built more carelessly. This module is what mines both.

The point is not any single extractor. It is that an operator who scrubs their
flagship leaves the same identity in a WordPress author endpoint on a second
site, a Gravatar hash in a third, a Google Doc link in a forgotten blog post,
an OAuth email in a login redirect. One page rarely has the answer; the union
of a portfolio's pages usually does.

## What is extracted, and how much each is worth

| Artifact | Predicate | Reliability | Why |
|---|---|---|---|
| WordPress author | REGISTRANT | STRONG | CMS publishes the account slug/name |
| Gravatar hash | PROFILE_BINDING | STRONG | Email MD5; reverses to a profile |
| Google Docs/Drive | PROFILE_BINDING | MODERATE | Doc IDs tie to an account |
| OAuth/login email | REGISTRANT | STRONG | `login_hint` is the operator's |
| Git config exposure | REGISTRANT | AUTHORITATIVE | committer name and email |
| `.env` leak | varies | STRONG | SMTP creds, API keys, DB names |
| WebFinger | PROFILE_BINDING | STRONG | account to canonical identity URIs |
| Service IDs (Sentry…) | SHARES_ANALYTICS_ID | STRONG | per-account; link a portfolio |
| HTML comments | (raw) | WEAK | build paths, staging hosts, notes |
| Response headers | varies | WEAK–MOD | X-Powered-By, backend hosts |
| Body names | PERSON_NAME | WEAK | 'Operated by', copyright lines |

Everything an operator authored is untrusted (see the injection guards). These
extractions are observations of *what was on the page*, which is different from
what the page *told the reader to conclude* — a regex match on a Gravatar hash
is fact; a sentence claiming an owner is not.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from attribution_graph import Claim, Identifier, IdKind, Predicate, Reliability

# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #

_EMAIL = re.compile(r"[\w.+\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,4}")

PATTERNS: dict[str, re.Pattern] = {
    # Google Docs / Drive / Sheets — the ID ties to an account
    "google_doc": re.compile(
        r"https?://docs\.google\.com/(?:document|spreadsheets|presentation|forms)"
        r"/d/([a-zA-Z0-9_\-]{20,})", re.I),
    "google_drive": re.compile(
        r"https?://drive\.google\.com/(?:file/d/|open\?id=)([a-zA-Z0-9_\-]{20,})", re.I),

    # Gravatar avatar hash (MD5 of a lowercased email)
    "gravatar": re.compile(
        r"(?:gravatar\.com/avatar/|secure\.gravatar\.com/avatar/)([a-f0-9]{32})", re.I),

    # OAuth login hints and prefilled addresses
    "oauth_login_hint": re.compile(r"login_hint=([\w.+\-]{1,64}@[\w.\-]{2,})", re.I),
    "oauth_email_param": re.compile(
        r"[?&](?:email|user|username|account)=([\w.+\-]{1,64}@[\w.\-]{2,})", re.I),

    # Service / product IDs that are per-account (link a portfolio like an
    # analytics ID does)
    "sentry_dsn": re.compile(
        r"https://([a-f0-9]{32})@[\w.\-]*sentry\.io", re.I),
    "intercom_app": re.compile(r"intercom[^\n]{0,40}?app_id[\"'\s:=]+([a-z0-9]{6,10})", re.I),
    "hotjar": re.compile(r"hjid[\"'\s:=]+(\d{6,8})", re.I),
    "mixpanel": re.compile(r"mixpanel[^\n]{0,60}?token[\"'\s:=]+([a-f0-9]{32})", re.I),
    "crisp_id": re.compile(r"CRISP_WEBSITE_ID[\"'\s=]+([a-f0-9\-]{36})", re.I),
    "stripe_pk": re.compile(r"\b(pk_live_[A-Za-z0-9]{20,})", re.I),

    # WebFinger / Mastodon rel=me (attributes may be unquoted, either order)
    "rel_me": re.compile(
        r"""<a\b[^>]*\brel=["']?me["']?[^>]*\bhref=["']?([^"'\s>]+)""", re.I),

    # Committer identity if a .git or repo path is exposed inline
    "git_email": re.compile(
        r"""(?:author|committer|user\.email)[\s:="']+"""
        r"([\w.+\-]{1,64}@[\w.\-]{2,})", re.I),
}

#: HTML comment bodies, minus conditional-IE and templating noise.
_COMMENT = re.compile(r"<!--(?!\[if)(?!\s*/?(?:ko|vue|ng|react))\s*(.*?)-->", re.S)

#: WordPress signals in a page body.
_WP_JSON_LINK = re.compile(r'href=["\']([^"\']*/wp-json/[^"\']*)["\']', re.I)
_WP_AUTHOR = re.compile(r"/author/([a-z0-9][\w\-]{1,60})/?", re.I)
_WP_GENERATOR = re.compile(
    r'name=["\']?generator["\']?[^>]*content=["\']?WordPress\s*([\d.]*)', re.I)

#: Names in body copy. Conservative: a bare capitalised phrase is not a name.
_BODY_NAME = re.compile(
    r"(?:operated by|owned by|run by|founded by|created by|author[:\s]|"
    r"copyright\s+(?:©\s*)?(?:\d{4}\s+)?|©\s*\d{4}\s+|a\s+project\s+by)"
    r"\s+([A-Z][\w.'\-]+(?:\s+[A-Z][\w.'\-]+){0,3})", re.I)

#: Developer / infrastructure hostnames that leak an origin or staging box.
_INTERNAL_HOST = re.compile(
    r"\b((?:staging|dev|test|origin|backend|api|admin|internal|old|beta|www\d)"
    r"[\w\-]*\.[\w.\-]+\.[a-z]{2,})\b", re.I)

#: Response headers worth keeping.
_KEEP_HEADERS = frozenset({
    "server", "x-powered-by", "via", "x-served-by", "x-backend-server",
    "x-generator", "x-drupal-cache", "x-aspnet-version", "cf-ray",
    "x-amz-cf-id", "x-vercel-id", "fly-request-id",
})


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #

@dataclass
class Extraction:
    domain: str
    source_url: str
    claims: list[Claim] = field(default_factory=list)
    artifacts: dict[str, list[str]] = field(default_factory=dict)
    #: Identifiers usable to pivot to sibling domains (service IDs, gravatar).
    pivot_seeds: list[Identifier] = field(default_factory=list)

    def add(self, kind: str, value: str) -> None:
        vals = self.artifacts.setdefault(kind, [])
        if value not in vals:
            vals.append(value)

    @property
    def yielded_identity(self) -> bool:
        """Whether this page produced anything that could name a person."""
        naming = {"wordpress_author", "gravatar", "oauth_email", "git_email",
                  "body_name", "env_leak"}
        return any(k in self.artifacts for k in naming)


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #

def extract_artifacts(
    body: str,
    domain: str,
    source_url: str = "",
    *,
    headers: dict[str, str] | None = None,
) -> Extraction:
    """Mine a page body (and optional headers) for identity artifacts."""
    ex = Extraction(domain=domain, source_url=source_url or f"https://{domain}/")
    subject = Identifier(IdKind.DOMAIN, domain)
    group = f"body|{domain}"

    def claim(pred, obj, rel, coll, **raw):
        ex.claims.append(Claim(
            subject=subject, predicate=pred, object=obj, collector=f"body:{coll}",
            source_url=ex.source_url, reliability=rel,
            correlation_group=group, raw=raw))

    # -- regex-driven identifiers ------------------------------------------- #
    for kind, pat in PATTERNS.items():
        for m in pat.finditer(body):
            value = m.group(1)
            ex.add(kind, value)

            if kind in ("google_doc", "google_drive"):
                claim(Predicate.PROFILE_BINDING,
                      Identifier(IdKind.URL, f"gdoc:{value}"),
                      Reliability.MODERATE, kind,
                      note="Google doc/drive ID ties to an account")
            elif kind == "gravatar":
                obj = Identifier(IdKind.GRAVATAR_HASH, value.lower())
                claim(Predicate.PROFILE_BINDING, obj, Reliability.STRONG, kind)
                ex.pivot_seeds.append(obj)
            elif kind in ("oauth_login_hint", "oauth_email_param", "git_email"):
                ex.add("oauth_email" if "oauth" in kind else "git_email", value)
                claim(Predicate.REGISTRANT, Identifier(IdKind.EMAIL, value.lower()),
                      Reliability.STRONG if "git" in kind else Reliability.STRONG,
                      kind)
            elif kind == "rel_me":
                ex.add("webfinger", value)
                claim(Predicate.PROFILE_BINDING, Identifier(IdKind.URL, value),
                      Reliability.STRONG, "webfinger")
            elif kind in ("sentry_dsn", "intercom_app", "hotjar", "mixpanel",
                          "crisp_id", "stripe_pk"):
                obj = Identifier(IdKind.ANALYTICS_ID, f"{kind}:{value}")
                claim(Predicate.SHARES_ANALYTICS_ID, obj, Reliability.STRONG, kind,
                      note="per-account service ID; links a portfolio")
                ex.pivot_seeds.append(obj)

    # -- analytics / tag IDs (primary sibling pivot) ------------------------ #
    from .collectors.analytics import extract_ids
    for scheme, val, _ in extract_ids(body):
        obj = Identifier(IdKind.ANALYTICS_ID, f"{scheme}:{val}")
        ex.add("analytics_id", f"{scheme}:{val}")
        claim(Predicate.SHARES_ANALYTICS_ID, obj, Reliability.AUTHORITATIVE,
              "analytics", note="page-embedded analytics/tag ID")
        ex.pivot_seeds.append(obj)

    # -- WordPress ---------------------------------------------------------- #
    if (_WP_GENERATOR.search(body) or "/wp-content/" in body
            or "/wp-json/" in body or _WP_AUTHOR.search(body)):
        ex.add("wordpress", "detected")
        for m in _WP_AUTHOR.finditer(body):
            slug = m.group(1).lower()
            if slug in ("admin", "wp-admin", "user"):
                continue
            ex.add("wordpress_author", slug)
            claim(Predicate.REGISTRANT,
                  Identifier(IdKind.HANDLE, f"wp:{domain}:{slug}"),
                  Reliability.STRONG, "wordpress_author",
                  note="author slug from a WordPress site")
        for m in _WP_JSON_LINK.finditer(body):
            ex.add("wp_json_endpoint", m.group(1))

    # -- HTML comments ------------------------------------------------------ #
    for m in _COMMENT.finditer(body):
        text = m.group(1).strip()
        if len(text) < 4 or len(text) > 400:
            continue
        ex.add("html_comment", text[:200])
        for hm in _INTERNAL_HOST.finditer(text):
            host = hm.group(1).lower()
            ex.add("internal_host", host)
            same_apex = host.endswith(domain.split(".", 1)[-1])
            claim(Predicate.CO_HOSTED, Identifier(IdKind.DOMAIN, host),
                  Reliability.WEAK, "html_comment",
                  note="hostname disclosed in an HTML comment",
                  same_apex=same_apex)
        for em in _EMAIL.findall(text):
            ex.add("comment_email", em.lower())
            claim(Predicate.PROFILE_BINDING, Identifier(IdKind.EMAIL, em.lower()),
                  Reliability.WEAK, "html_comment")

    # -- body names --------------------------------------------------------- #
    for m in _BODY_NAME.finditer(body):
        name = m.group(1).strip()
        if len(name) < 4 or name.lower() in ("all rights", "the author"):
            continue
        ex.add("body_name", name)
        claim(Predicate.REGISTRANT, Identifier(IdKind.PERSON_NAME, name),
              Reliability.WEAK, "body_name",
              note="attribution phrase in page copy")

    # -- response headers --------------------------------------------------- #
    if headers:
        for h, v in headers.items():
            hl = h.lower()
            if hl not in _KEEP_HEADERS or not v:
                continue
            ex.add(f"header:{hl}", v)
            for hm in _INTERNAL_HOST.finditer(v):
                claim(Predicate.CO_HOSTED,
                      Identifier(IdKind.DOMAIN, hm.group(1).lower()),
                      Reliability.MODERATE, "response_header",
                      note=f"origin hostname in {hl} header")

    return ex


def gravatar_hash(email: str) -> str:
    """The Gravatar hash of an email.

    Delegates to the canonical implementation in ``fingerprint.py``. Three
    copies of this existed at one point and a same-named function in two
    modules is how that drift begins, so this one forwards rather than
    reimplements.
    """
    from .fingerprint import gravatar_hash as _canonical

    return _canonical(email)



# --------------------------------------------------------------------------- #
# Sensitive-path probing (opt-in)
# --------------------------------------------------------------------------- #

#: Paths that expose operator identity when misconfigured. Probing these is
#: reconnaissance, not passive collection, so it is gated behind an explicit
#: flag and every fetch is audit-logged. On a domain you are not authorised to
#: test, requesting these may itself be unlawful.
SENSITIVE_PATHS: dict[str, tuple[str, str]] = {
    "/.git/config": ("git_config", "committer name and email, remote URLs"),
    "/.env": ("env_leak", "SMTP credentials, API keys, database names"),
    "/wp-json/wp/v2/users": ("wp_users_api", "WordPress author accounts as JSON"),
    "/.well-known/webfinger": ("webfinger", "account-to-identity mapping"),
    "/server-status": ("apache_status", "active requests, client IPs, vhosts"),
    "/phpinfo.php": ("phpinfo", "server paths, environment, module config"),
    "/.DS_Store": ("ds_store", "directory listing of the deploy"),
    "/config.json": ("config_leak", "application configuration"),
    "/backup.sql": ("sql_dump", "database contents"),
}

_GIT_IDENT = re.compile(r"(?:name|email)\s*=\s*(.+)", re.I)


async def probe_sensitive_paths(
    fetcher, domain: str, *, enabled: bool = False,
    audit=None,
) -> Extraction:
    """Fetch known identity-leaking paths. Off by default.

    This is active reconnaissance and is treated as such: it does not run unless
    ``enabled=True``, and each request is passed to ``audit`` if provided. The
    caller is responsible for having authorisation to probe the target; the
    ``case.yaml`` authorization field is where that is recorded.
    """
    ex = Extraction(domain=domain, source_url=f"https://{domain}/")
    if not enabled:
        return ex

    subject = Identifier(IdKind.DOMAIN, domain)
    group = f"probe|{domain}"

    for path, (kind, _desc) in SENSITIVE_PATHS.items():
        url = f"https://{domain}{path}"
        if audit:
            audit("probe", url, kind)
        r = await fetcher.get(url, allow_html=True)
        if not r or getattr(r, "status", 0) != 200 or not r.text:
            continue
        body = r.text
        ex.add(kind, url)

        if kind == "git_config":
            for m in _GIT_IDENT.finditer(body):
                val = m.group(1).strip()
                if "@" in val:
                    ex.claims.append(Claim(
                        subject=subject, predicate=Predicate.REGISTRANT,
                        object=Identifier(IdKind.EMAIL, val.lower()),
                        collector="probe:git_config", source_url=url,
                        reliability=Reliability.AUTHORITATIVE,
                        correlation_group=group,
                        raw={"basis": "committer email in exposed .git/config"}))
                elif len(val) > 2:
                    ex.claims.append(Claim(
                        subject=subject, predicate=Predicate.REGISTRANT,
                        object=Identifier(IdKind.PERSON_NAME, val),
                        collector="probe:git_config", source_url=url,
                        reliability=Reliability.STRONG,
                        correlation_group=group,
                        raw={"basis": "committer name in exposed .git/config"}))

        elif kind == "env_leak":
            for em in _EMAIL.findall(body):
                ex.claims.append(Claim(
                    subject=subject, predicate=Predicate.PROFILE_BINDING,
                    object=Identifier(IdKind.EMAIL, em.lower()),
                    collector="probe:env_leak", source_url=url,
                    reliability=Reliability.STRONG, correlation_group=group,
                    raw={"basis": "address in an exposed .env file"}))

        elif kind == "wp_users_api":
            try:
                users = json.loads(body)
            except json.JSONDecodeError:
                users = []
            for u in users if isinstance(users, list) else []:
                if u.get("name"):
                    ex.claims.append(Claim(
                        subject=subject, predicate=Predicate.REGISTRANT,
                        object=Identifier(IdKind.PERSON_NAME, u["name"]),
                        collector="probe:wp_users_api", source_url=url,
                        reliability=Reliability.STRONG,
                        correlation_group=group,
                        raw={"slug": u.get("slug"),
                             "basis": "WordPress users REST endpoint"}))

    return ex
