"""Egress control: where a request appears to come from, and why it matters.

## The same URL is not the same page

Content varies by the requester's apparent location, and for attribution work
that variation is often the finding rather than a nuisance:

- an imprint page showing a German entity to EU visitors and nothing elsewhere
- ``ads.txt`` differing by region because the operator sells inventory through
  different partners per market
- a company register that returns results only to requests from inside the
  jurisdiction
- geo-blocked content that reveals a market the operator serves and does not
  advertise

So the exit used for a request is **part of the evidence**, not a transport
detail. A capture that does not record its egress is not reproducible even in
principle: a reviewer re-fetching from a different country and getting different
bytes cannot tell whether the page changed or the vantage point did.

## Divergence is a claim, not an error

``GeoDivergence`` fetches one URL from several exits and compares. Identical
responses are unremarkable. Different responses mean the operator is
representing itself differently to different audiences, and that belongs in the
report with both captures preserved.

## Credentials never enter the package

Proxy usernames and passwords are read from the environment, held only in
memory, and redacted from every manifest, log and audit entry. A proxy URL in an
evidence package is a credential leak in a file designed to be shared.

## On residential proxy networks

Datacenter proxies are unremarkable infrastructure. Residential and mobile
networks are not: the exit is a real person's connection, and consent is
frequently obtained by bundling an SDK into a free application whose users do
not meaningfully understand what they agreed to.

That is a decision for the operator of this tool, not for the tool. What the
tool does is refuse to make it invisible — the network type is recorded in the
case file and written into the evidence manifest and declaration draft, so a run
that used residential exits says so on its face.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from urllib.parse import quote, urlunsplit


class NetworkType(StrEnum):
    """What kind of exit a proxy provides. Recorded, never hidden."""

    DIRECT = "direct"
    DATACENTER = "datacenter"
    ISP = "isp"
    RESIDENTIAL = "residential"
    MOBILE = "mobile"
    UNKNOWN = "unknown"


#: Network types whose exits are private individuals' connections. Flagged in
#: the manifest and the declaration draft so a run cannot use them silently.
CONSENT_SENSITIVE = frozenset({NetworkType.RESIDENTIAL, NetworkType.MOBILE})


@dataclass(frozen=True)
class ProviderProfile:
    """How one provider expects to be addressed.

    They all speak HTTP CONNECT or SOCKS5; what differs is the endpoint and how
    country and session selection are encoded into the username. Profiles keep
    that convention out of user configuration.
    """

    name: str
    host: str
    port: int
    #: Format string for the username. ``{user}``, ``{country}``, ``{session}``.
    username_template: str
    scheme: str = "http"
    supports_country: bool = True
    supports_sticky_session: bool = True
    note: str = ""
    #: Network types this endpoint actually provides.
    #:
    #: `network` was a free caller label while the profile chose the endpoint,
    #: so `provider: oxylabs, network: datacenter` was accepted and routed to
    #: pr.oxylabs.io -- the profile's own documented *residential* endpoint. The
    #: record then declared datacenter and consent_sensitive=false, so both the
    #: provenance and the residential safeguard were wrong at once.
    networks: frozenset = frozenset()
    #: Network types this endpoint actually provides.
    #:
    #: `network` used to be a free caller label while the profile chose the
    #: endpoint, so `provider: oxylabs, network: datacenter` recorded
    #: consent_sensitive=False while routing to pr.oxylabs.io -- the residential
    #: endpoint. Both the provenance and the residential safeguard were wrong.
    networks: tuple = ()


#: Conventions as documented by each provider. Verify against current docs
#: before a run that matters -- these change without notice, and a malformed
#: username usually fails as an auth error rather than anything informative.
PROVIDERS: dict[str, ProviderProfile] = {
    "oxylabs": ProviderProfile(
        "oxylabs", "pr.oxylabs.io", 7777,
        "customer-{user}-cc-{country}-sessid-{session}",
        networks=(NetworkType.RESIDENTIAL, NetworkType.MOBILE),
        note="residential endpoint; use oxylabs_datacenter for dc.oxylabs.io"),
    "oxylabs_datacenter": ProviderProfile(
        "oxylabs_datacenter", "dc.oxylabs.io", 8001,
        "user-{user}-cc-{country}", supports_sticky_session=False,
        networks=(NetworkType.DATACENTER,)),
    "brightdata": ProviderProfile(
        "brightdata", "brd.superproxy.io", 22225,
        "brd-customer-{user}-zone-residential-country-{country}-session-{session}",
        networks=(NetworkType.RESIDENTIAL, NetworkType.MOBILE)),
    "smartproxy": ProviderProfile(
        "smartproxy", "gate.smartproxy.com", 7000,
        "user-{user}-country-{country}-session-{session}",
        networks=(NetworkType.RESIDENTIAL, NetworkType.MOBILE)),
    "netnut": ProviderProfile(
        "netnut", "gw.ntnt.io", 5959, "{user}-cc-{country}",
        networks=(NetworkType.RESIDENTIAL, NetworkType.ISP)),
    "zyte": ProviderProfile(
        "zyte", "proxy.crawlera.com", 8011, "{user}",
        supports_country=False, supports_sticky_session=False,
        networks=(NetworkType.DATACENTER,),
        note="country selection is per-zone, configured in the Zyte dashboard"),
    "generic": ProviderProfile(
        "generic", "", 0, "{user}", supports_country=False,
        supports_sticky_session=False,
        note="any HTTP/SOCKS proxy; set host and port in the case file"),
}


class ProxyError(RuntimeError):
    """Configuration that would silently produce wrong or unattributed results."""


@dataclass
class Egress:
    """One configured vantage point.

    ``password_env`` names an environment variable. The value is read at build
    time and never stored on the instance, so a serialised ``Egress`` cannot
    leak a credential.
    """

    label: str
    country: str = ""                       # ISO 3166-1 alpha-2, lowercase
    provider: str = "direct"
    network: NetworkType = NetworkType.DIRECT
    host: str = ""
    port: int = 0
    username: str = ""
    password_env: str = ""
    session: str = ""
    scheme: str = "http"
    note: str = ""

    def __post_init__(self) -> None:
        self.country = (self.country or "").strip().lower()
        if self.country and not re.fullmatch(r"[a-z]{2}", self.country):
            raise ProxyError(
                f"country must be an ISO 3166-1 alpha-2 code, got {self.country!r}")
        # A proxied egress left at the DIRECT default has not declared a
        # network, and treating that as a positive claim of "direct" would make
        # every unlabelled proxy contradict its own endpoint. UNKNOWN skips
        # validation and is recorded as undeclared.
        if self.provider != "direct" and self.network is NetworkType.DIRECT:
            self.network = NetworkType.UNKNOWN

        if self.provider == self.ENVIRONMENT:
            # Its endpoint is whatever the environment says, so there is no
            # profile to validate against and no country claim to check.
            self.network = NetworkType.UNKNOWN
            if not self.note:
                self.note = ("ambient proxy, declared explicitly by the "
                             "operator; its exit point is not ours to assert")
        elif self.provider not in PROVIDERS and self.provider != "direct":
            raise ProxyError(
                f"unknown provider {self.provider!r}; known: "
                f"{', '.join(sorted(PROVIDERS))}, or 'direct'")

        # The declared network must match what the endpoint actually provides.
        # A free caller label meant `oxylabs` + `datacenter` routed to the
        # residential endpoint while recording consent_sensitive=false, so the
        # provenance and the safeguard were both wrong.
        if self.provider not in ("direct", self.ENVIRONMENT):
            profile = PROVIDERS[self.provider]
            if (profile.networks and self.network is not NetworkType.UNKNOWN
                    and self.network not in profile.networks):
                allowed = ", ".join(sorted(n.value for n in profile.networks))
                raise ProxyError(
                    f"egress {self.label!r}: provider {self.provider!r} serves "
                    f"{allowed} exits, but network is declared "
                    f"{self.network.value!r}. Either declare the real network "
                    f"type or pick the provider profile for the endpoint you "
                    f"want -- a mislabelled exit corrupts both the evidence "
                    f"record and the consent-sensitivity check.")
            if self.network is NetworkType.UNKNOWN and len(profile.networks) == 1:
                # Unambiguous profile: fill it in rather than leaving the
                # evidence record saying "unknown".
                self.network = next(iter(profile.networks))

    def validate_network(self) -> None:
        """Reject a declared network the chosen endpoint does not provide.

        The label drives the consent-sensitivity safeguard and the evidence
        record, so accepting a caller's word for it made both wrong at once:
        `oxylabs` + `datacenter` recorded a non-sensitive datacenter exit while
        routing to the residential endpoint.
        """
        if self.is_direct or self.provider == self.ENVIRONMENT:
            # The environment's proxy has no profile to validate against: its
            # exit point belongs to whoever runs the sandbox, and claiming to
            # know it would be the fabrication this check exists to prevent.
            return
        profile = PROVIDERS[self.provider]
        if not profile.networks or self.network is NetworkType.UNKNOWN:
            return
        if self.network not in profile.networks:
            allowed = ", ".join(n.value for n in profile.networks)
            raise ProxyError(
                f"egress {self.label!r}: provider {self.provider!r} routes to "
                f"{profile.host}, which provides {allowed}, but the case file "
                f"declares network={self.network.value!r}. Use a provider "
                "profile matching the endpoint product -- a mislabelled network "
                "makes both the evidence record and the consent-sensitivity "
                "check wrong.")

    @property
    def is_direct(self) -> bool:
        return self.provider == "direct"

    @property
    def consent_sensitive(self) -> bool:
        return self.network in CONSENT_SENSITIVE

    #: An egress whose proxy URL comes from this machine's own environment.
    #: Declared, never ambient: `trust_env=False` on the client is deliberate,
    #: because a proxy picked up silently would make the evidence manifest
    #: record `direct` while the traffic left through someone else's exit.
    #: Naming it in the case file keeps the provenance true AND makes the tool
    #: usable inside a sandbox whose only route out is an HTTP proxy -- which
    #: is every agent sandbox, where a direct connection cannot resolve
    #: anything and the whole run reports itself blocked.
    ENVIRONMENT = "environment"

    def environment_proxy(self) -> str:
        """The ambient proxy, read at use time and never stored."""
        for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy",
                    "HTTP_PROXY", "http_proxy"):
            value = os.environ.get(var, "").strip()
            if value:
                return value
        raise ProxyError(
            f"egress {self.label!r} is declared as provider 'environment', but "
            "no HTTPS_PROXY, ALL_PROXY or HTTP_PROXY is set in this "
            "environment. Unset it in the case file, or set the variable.")

    def proxy_url(self) -> str | None:
        """The URL to hand an HTTP client. Never logged, never serialised."""
        if self.provider == self.ENVIRONMENT:
            return self.environment_proxy()
        if self.is_direct:
            return None

        profile = PROVIDERS[self.provider]
        host = self.host or profile.host
        port = self.port or profile.port
        if not host or not port:
            raise ProxyError(
                f"egress {self.label!r}: provider {self.provider!r} needs an "
                "explicit host and port")

        if self.country and not profile.supports_country:
            raise ProxyError(
                f"egress {self.label!r}: {self.provider} does not support "
                "per-request country selection; configure it provider-side and "
                "leave `country` unset, or the run will silently exit from the "
                "wrong place")

        self.validate_network()

        password = os.environ.get(self.password_env, "") if self.password_env else ""
        if not password:
            raise ProxyError(
                f"egress {self.label!r}: set {self.password_env or '<password_env>'} "
                "in the environment. Credentials are never read from the case "
                "file, which is a shareable artifact.")

        user = profile.username_template.format(
            user=self.username, country=self.country or "",
            session=self.session or _session_id(self.label))
        netloc = f"{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"
        return urlunsplit((self.scheme or profile.scheme, netloc, "", "", ""))

    # -- record ------------------------------------------------------------- #

    def to_record(self) -> dict:
        """What goes into the evidence manifest. Credential-free by construction."""
        rec = {
            "label": self.label,
            "provider": self.provider,
            "network": self.network.value,
            "country": self.country or "unspecified",
            "direct": self.is_direct,
        }
        if self.consent_sensitive:
            rec["consent_note"] = (
                "Exits on this network are individual subscribers' connections. "
                "Consent is commonly obtained by bundling an SDK into a free "
                "application. Recorded here so the run cannot use them silently.")
        if self.note:
            rec["note"] = self.note
        return rec

    def describe(self) -> str:
        if self.is_direct:
            return "direct (no proxy)"
        where = self.country.upper() if self.country else "provider default"
        s = f"{self.provider} / {self.network.value} / exit {where}"
        return s + "  [consent-sensitive]" if self.consent_sensitive else s


def _session_id(label: str) -> str:
    """Stable per-label session so one egress keeps one exit IP across a run.

    Rotating mid-run would mean captures attributed to one vantage point came
    from several, which makes a geo comparison meaningless.
    """
    seed = f"{label}|{datetime.now(timezone.utc):%Y%m%d%H}"
    return hashlib.sha256(seed.encode()).hexdigest()[:12]


REDACT = re.compile(r"://[^/@\s]+:[^/@\s]+@")


def redact(text: str) -> str:
    """Strip credentials from anything about to be written or logged."""
    return REDACT.sub("://<redacted>@", text)


# --------------------------------------------------------------------------- #
# Geo divergence
# --------------------------------------------------------------------------- #

@dataclass
class VantageCapture:
    egress_label: str
    country: str
    status: int | None
    body_sha256: str
    body_bytes: int
    fetched_at: datetime
    error: str = ""


@dataclass
class GeoDivergence:
    """One URL fetched from several vantage points.

    Divergence is a claim about the operator, not a transport problem: serving
    different corporate details to different regions is a decision someone made.
    """

    url: str
    captures: list[VantageCapture] = field(default_factory=list)

    @property
    def successful(self) -> list[VantageCapture]:
        return [c for c in self.captures if c.status == 200 and not c.error]

    @property
    def distinct_bodies(self) -> int:
        return len({c.body_sha256 for c in self.successful})

    @property
    def diverges(self) -> bool:
        return self.distinct_bodies > 1

    @property
    def blocked_from(self) -> list[str]:
        """Vantage points that could not retrieve the page at all."""
        return [c.country or c.egress_label for c in self.captures
                if c.error or (c.status is not None and c.status >= 400)]

    def groups(self) -> dict[str, list[str]]:
        """body hash -> the countries that received it."""
        out: dict[str, list[str]] = {}
        for c in self.successful:
            out.setdefault(c.body_sha256, []).append(c.country or c.egress_label)
        return out

    def to_record(self) -> dict:
        return {
            "url": self.url,
            "vantage_points": len(self.captures),
            "distinct_bodies": self.distinct_bodies,
            "diverges": self.diverges,
            "blocked_from": self.blocked_from,
            "groups": {h[:16]: sorted(v) for h, v in self.groups().items()},
            "captures": [
                {"egress": c.egress_label, "country": c.country,
                 "status": c.status, "body_sha256": c.body_sha256,
                 "body_bytes": c.body_bytes,
                 "fetched_at": c.fetched_at.isoformat(),
                 **({"error": c.error} if c.error else {})}
                for c in self.captures
            ],
        }

    def render(self) -> str:
        lines = [f"{self.url}",
                 f"  fetched from {len(self.captures)} vantage point(s)"]
        if not self.successful:
            lines.append("  retrieved from none of them")
            return "\n".join(lines)

        if self.diverges:
            lines.append(f"  DIVERGES: {self.distinct_bodies} distinct responses")
            for h, countries in sorted(self.groups().items()):
                lines.append(f"    {h[:12]}… served to {', '.join(sorted(countries))}")
            lines.append("  The operator is representing itself differently by "
                         "region. Both responses are preserved.")
        else:
            lines.append("  identical from every vantage point")

        if self.blocked_from:
            lines.append(f"  blocked from: {', '.join(self.blocked_from)}")
            lines.append("  A geo-block is itself a statement about which "
                         "markets the operator serves.")
        return "\n".join(lines)


@dataclass
class EgressPool:
    """The vantage points configured for a run."""

    egresses: list[Egress] = field(default_factory=list)
    default_label: str = ""

    @classmethod
    def from_case(cls, config: list[dict] | None, default: str = "") -> EgressPool:
        """Build from the ``egress:`` block of a case file."""
        if not config:
            return cls([Egress(label="direct")], default_label="direct")
        pool = [Egress(**{**e, "network": NetworkType(e.get("network", "unknown"))})
                for e in config]
        return cls(pool, default_label=default or pool[0].label)

    def get(self, label: str = "") -> Egress:
        want = label or self.default_label
        for e in self.egresses:
            if e.label == want:
                return e
        raise ProxyError(
            f"no egress labelled {want!r}; configured: "
            f"{', '.join(e.label for e in self.egresses)}")

    def for_country(self, country: str) -> Egress | None:
        c = (country or "").lower()
        return next((e for e in self.egresses if e.country == c), None)

    @property
    def consent_sensitive(self) -> list[Egress]:
        return [e for e in self.egresses if e.consent_sensitive]

    def to_record(self) -> list[dict]:
        return [e.to_record() for e in self.egresses]

    def manifest_note(self) -> str:
        """Text for the evidence manifest and declaration draft."""
        if all(e.is_direct for e in self.egresses):
            return "All requests were made directly, without a proxy."
        parts = [
            f"Requests were made through {len(self.egresses)} configured "
            f"vantage point(s): " +
            "; ".join(e.describe() for e in self.egresses) + ".",
            "Content served over the web varies by the requester's apparent "
            "location, so the exit used is recorded per capture. A reviewer "
            "re-fetching from elsewhere may receive different bytes without "
            "the page having changed.",
        ]
        if self.consent_sensitive:
            parts.append(
                f"{len(self.consent_sensitive)} vantage point(s) used "
                "residential or mobile exits, which are individual "
                "subscribers' connections. This is recorded so the run does "
                "not rely on them silently.")
        return " ".join(parts)


def probe_url(scheme: str = "https") -> str:
    """An endpoint that reports the apparent source address.

    Worth calling once per egress at the start of a run: a proxy that silently
    fails open sends traffic from the analyst's own address, and finding that
    out from the evidence manifest afterwards is too late.
    """
    _ = scheme
    return "https://api.ipify.org?format=json"


def verify_egress_country(reported_country: str, expected: str) -> tuple[bool, str]:
    """Compare an observed exit country against what was configured."""
    if not expected:
        return True, "no country was requested"
    got = (reported_country or "").lower()
    if got == expected.lower():
        return True, f"exit confirmed in {got.upper()}"
    return False, (
        f"exit is in {got.upper() or 'an unknown country'} but "
        f"{expected.upper()} was requested — the proxy may have failed open, "
        "which would attribute captures to a vantage point they did not use")


@dataclass
class PreflightResult:
    """What one egress actually turned out to be, before the run uses it."""
    label: str
    reached: bool = False
    apparent_address: str = ""
    apparent_country: str = ""
    failed_open: bool = False
    note: str = ""

    def render(self) -> str:
        if not self.reached:
            return f"egress `{self.label}`: could not be checked — {self.note}"
        where = self.apparent_address or "an address it did not report"
        tail = f", {self.apparent_country.upper()}" if self.apparent_country else ""
        if self.failed_open:
            return (f"egress `{self.label}`: FAILED OPEN — traffic is leaving "
                    f"from {where}{tail}. {self.note}")
        return f"egress `{self.label}`: exits from {where}{tail}"


async def preflight(fetcher, pool, *, label: str = "") -> PreflightResult:
    """Check what an egress really is, once, before the run depends on it.

    A proxy that fails open sends traffic from the analyst's own address while
    every capture in the manifest claims the configured vantage point. Until
    now `probe_url` and `verify_egress_country` both existed for this and
    neither had a caller, so the only way to find out was to read the manifest
    afterwards -- by which time the captures carry a vantage point they never
    had, and a run performed from a jurisdiction the case was written to avoid
    cannot be undone.

    Fail-open is detected by comparison, not by geolocation: probe through the
    configured egress, probe again directly, and if both report the SAME
    apparent address then the proxy is not carrying the traffic. That needs no
    geo service and gives a definite answer. A declared country cannot be
    confirmed from an address alone, so when one is declared this says the
    claim is unverified rather than implying it was checked -- an unverified
    claim stated as verified is worse than no check at all.

    Deliberately cheap and deliberately non-fatal: at most two requests, and a
    failure to reach the probe is reported as "could not be checked", never as
    a verdict about the egress. A sandbox that blocks the probe host but allows
    the targets is a working run.
    """
    egress = pool.get(label)
    result = PreflightResult(label=egress.label)

    seen = await _apparent_address(fetcher, egress.label)
    if seen is None:
        result.note = "the probe request was blocked or returned nothing"
        return result
    result.reached = True
    result.apparent_address = seen

    if not egress.is_direct:
        # The baseline has to come from an egress that is actually direct.
        # Omitting the label would fall through to the pool default, which is
        # the proxy being tested -- a comparison of the proxy against itself,
        # which always agrees and would have reported every proxy healthy.
        plain = next((e for e in pool.egresses if e.is_direct), None)
        baseline = (await _apparent_address(fetcher, plain.label)
                    if plain is not None else None)
        if baseline is None:
            result.note = ("no direct egress is configured to compare against, "
                           "so whether the proxy is carrying the traffic is "
                           "unverified here")
        elif baseline == seen:
            result.failed_open = True
            result.note = ("a direct request reports the same address, so the "
                           "proxy is not carrying this traffic and every "
                           "capture would record a vantage point it did not "
                           "use")
        else:
            result.note = "a direct request reports a different address"

    if egress.country:
        # Wired, but only where it can mean something. The probe reports an
        # address; the country behind it is not observable without a geo
        # source this toolkit does not ship.
        ok, why = verify_egress_country(result.apparent_country, egress.country)
        claim = (why if result.apparent_country else
                 f"the declared exit country {egress.country.upper()} is "
                 "UNVERIFIED: an address does not establish a country")
        result.note = f"{result.note}; {claim}" if result.note else claim
        if not ok and result.apparent_country:
            result.failed_open = True

    return result


async def _apparent_address(fetcher, label: str):
    """The source address this environment appears to have through `label`."""
    import json as _json

    try:
        r = await fetcher.get(probe_url(), egress=label)
    except Exception:                       # noqa: BLE001 - absence is the signal
        return None
    if r is None:
        return None
    try:
        return str(_json.loads(r.text).get("ip", "") or "") or None
    except (ValueError, AttributeError, TypeError):
        text = (getattr(r, "text", "") or "").strip()
        return text[:64] or None
