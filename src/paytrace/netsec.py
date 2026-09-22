"""URL safety: SSRF prevention for a fetcher driven by adversary-controlled data.

This is not a theoretical concern here. The toolkit fetches URLs built from
fields inside files written by the entity under investigation:

    ads.txt:   `169.254.169.254, 1, DIRECT`  -> https://169.254.169.254/sellers.json
    ads.txt:   `OWNERDOMAIN=localhost`       -> https://localhost/ads.txt
    imprint:   a link to http://10.0.0.5:8080/

The first reaches the cloud instance metadata endpoint on AWS, GCP and Azure.
The second and third reach whatever is listening on the host or in the VPC that
the investigation is running from. An operator publishes one line in a public
file and gets a request from inside your network.

Four checks, all of which have to pass:

1. **Scheme** — http and https only. No file://, gopher://, ftp://, data:.
2. **Host syntax** — a real hostname or an explicitly permitted IP. Rejects
   userinfo (``https://evil.com@10.0.0.1/``), which is the classic parser
   confusion trick.
3. **Resolution** — every A/AAAA record the host resolves to must be a global
   unicast address. Blocks loopback, link-local, private, CGNAT, multicast and
   reserved ranges. This is the check that catches DNS rebinding to a private
   address, which host-string matching alone cannot.
4. **Port** — 80 and 443 by default. An investigation has no business on 22.

Redirects are re-checked, because a permitted host can redirect to a blocked
one and a fetcher that validates only the first URL is not validating anything.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})

#: Hostname syntax per RFC 1123, with a length cap. Deliberately strict:
#: anything exotic is far more likely to be an attack than a real publisher.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

#: Hosts that are never legitimate investigation targets regardless of what
#: they resolve to.
BLOCKED_HOSTNAMES = frozenset({
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata", "metadata.google.internal", "metadata.goog",
    "instance-data", "instance-data.ec2.internal",
})

#: Ranges beyond what ``ipaddress`` already flags as non-global.
EXTRA_BLOCKED_NETS = [
    ipaddress.ip_network("169.254.169.254/32"),   # cloud metadata (AWS/GCP/Azure)
    ipaddress.ip_network("fd00:ec2::254/128"),    # AWS IMDSv6
    ipaddress.ip_network("100.64.0.0/10"),        # CGNAT
    ipaddress.ip_network("192.0.0.0/24"),         # IETF protocol assignments
]


class UrlRejected(ValueError):
    """Raised when a URL fails validation. Carries the reason for the audit log."""

    def __init__(self, url: str, reason: str) -> None:
        super().__init__(f"{reason}: {url}")
        self.url = url
        self.reason = reason


@dataclass
class UrlPolicy:
    """Per-run URL policy. Defaults are the safe ones."""

    allow_private: bool = False        # only for testing against local fixtures
    allow_ip_literals: bool = False    # PTR-style investigation, off by default
    allowed_ports: frozenset[int] = ALLOWED_PORTS
    extra_blocked_hosts: frozenset[str] = frozenset()
    #: Hosts explicitly permitted despite resolving privately. For a self-hosted
    #: yente or a local corpus service.
    allowlist: frozenset[str] = frozenset()
    rejections: list[tuple[str, str]] = field(default_factory=list)

    def record(self, url: str, reason: str) -> None:
        self.rejections.append((url, reason))


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if ip.is_loopback:
        return "resolves to loopback"
    if ip.is_link_local:
        return "resolves to link-local"
    if ip.is_private:
        return "resolves to a private address"
    if ip.is_multicast:
        return "resolves to multicast"
    if ip.is_reserved:
        return "resolves to a reserved address"
    if ip.is_unspecified:
        return "resolves to the unspecified address"
    for net in EXTRA_BLOCKED_NETS:
        if ip.version == net.version and ip in net:
            return f"resolves into {net} (cloud metadata or carrier NAT)"
    if not ip.is_global:
        return "does not resolve to a global unicast address"
    return None


def resolve_all(host: str) -> list[str]:
    """Every address the host resolves to. Overridable in tests."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return []
    return sorted({i[4][0] for i in infos})


#: host -> the addresses that passed validation, most recent check wins.
#:
#: Populated by check_url and consumed by the pinned transport. Process-local
#: and deliberately not persisted: a pin is only meaningful for the connection
#: that immediately follows its validation.
VALIDATED_ADDRESSES: dict[str, list[str]] = {}


def validated_addresses(host: str) -> list[str]:
    """Addresses approved for ``host`` by the most recent check_url call."""
    return list(VALIDATED_ADDRESSES.get(host, []))


def check_url(url: str, policy: UrlPolicy | None = None,
              resolver=resolve_all) -> str:
    """Validate a URL. Returns it unchanged, or raises ``UrlRejected``.

    ``resolver`` is injectable so tests do not depend on live DNS.
    """
    policy = policy or UrlPolicy()
    parts = urlsplit(url)

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise UrlRejected(url, f"scheme '{parts.scheme}' not permitted")

    # Userinfo lets `https://trusted.example@10.0.0.1/` read as trusted to a
    # human and resolve to the host after the @.
    if "@" in parts.netloc:
        raise UrlRejected(url, "userinfo in authority")

    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise UrlRejected(url, "no host")

    # urlsplit(...).port raises on a non-numeric or out-of-range port, which
    # turned a hostile redirect into an internal defect rather than a blocked
    # fetch. Every rejection path must produce UrlRejected.
    try:
        declared_port = parts.port
    except ValueError as e:
        raise UrlRejected(url, f"malformed port: {e}") from None

    port = declared_port or (443 if parts.scheme == "https" else 80)
    if port not in policy.allowed_ports:
        raise UrlRejected(url, f"port {port} not permitted")

    if host in policy.allowlist:
        return url

    if host in BLOCKED_HOSTNAMES or host in policy.extra_blocked_hosts:
        raise UrlRejected(url, f"host '{host}' is blocked")

    # Literal IP in the URL
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        if not policy.allow_ip_literals:
            raise UrlRejected(url, "IP literal hosts are not permitted")
        if not policy.allow_private and (reason := _is_blocked_ip(ip)):
            raise UrlRejected(url, reason)
        return url

    if not _HOSTNAME.match(host):
        raise UrlRejected(url, "malformed hostname")

    if policy.allow_private:
        return url

    addresses = resolver(host)
    if not addresses:
        raise UrlRejected(url, "host does not resolve")

    for addr in addresses:
        try:
            parsed = ipaddress.ip_address(addr)
        except ValueError:
            raise UrlRejected(url, f"unparseable address {addr}") from None
        # ALL addresses must pass. A host resolving to one public and one
        # private address is a rebinding attempt, not a misconfiguration.
        if reason := _is_blocked_ip(parsed):
            raise UrlRejected(url, f"{reason} ({addr})")

    # Record what was approved. Validating by hostname and then connecting by
    # hostname is two independent resolutions; the caller pins the socket to
    # these addresses so the second one cannot differ.
    VALIDATED_ADDRESSES[host] = list(addresses)
    return url


def is_safe(url: str, policy: UrlPolicy | None = None, resolver=resolve_all) -> bool:
    try:
        check_url(url, policy, resolver)
        return True
    except UrlRejected:
        return False


# --------------------------------------------------------------------------- #
# Host extraction from collected data
# --------------------------------------------------------------------------- #

def safe_host(value: str, policy: UrlPolicy | None = None,
              resolver=resolve_all) -> str | None:
    """Validate a bare hostname taken from collected data.

    Use this on any host pulled out of a file the subject controls: an
    ``ads.txt`` ad-system field, an ``OWNERDOMAIN`` value, a ``sellers.json``
    domain. Returns the normalised host, or ``None`` if it must not be fetched.
    """
    host = (value or "").strip().lower().rstrip(".")
    if not host or "/" in host or "@" in host or ":" in host:
        return None
    try:
        check_url(f"https://{host}/", policy, resolver)
    except UrlRejected:
        return None
    return host
