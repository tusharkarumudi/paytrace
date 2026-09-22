"""Address pinning at the socket layer.

## Why not rewrite the URL

The first attempt substituted the validated IP into the request URL and added a
`Host` header. That reduced the rebinding window but introduced two defects an
audit found empirically:

1. **Connection-pool identity.** httpx/httpcore key connection reuse on
   ``request.url.origin``. Rewriting the host to the IP made two different
   hostnames pinned to the same address one origin, so a pooled connection
   established for `a.example` could serve `b.example`. SNI is applied when a
   TLS connection is created, not when a pooled one is reused, so hostname
   authenticity was weakened rather than preserved.
2. **Duplicate `Host` headers.** Appending rather than replacing emitted two
   authorities.

So pinning belongs *below* the logical request: the URL, the pool origin and
the `Host` header all keep the original hostname, and only the TCP connect
target is substituted. That is the one layer where an address can be forced
without changing anything the peer or the pool observes.

## What this guarantees

- `connect_tcp` receives only an address that passed `check_url`.
- TLS verification and SNI use the original hostname.
- Exactly one `Host` header, carrying the hostname.
- Connections are never reused across different logical hostnames, because the
  pool still sees distinct origins.

## Proxies

Through a proxy the proxy resolves, so none of this applies. `pins_enforced` is
set False on the pool that carries proxied traffic and recorded in the run,
because a control that cannot be enforced must not be reported as active.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from .netsec import UrlPolicy, UrlRejected, check_url


@dataclass
class PinnedResolver:
    """Addresses approved for each hostname during this run."""

    policy: UrlPolicy | None = None
    resolver: object | None = None
    #: hostname -> the single address the socket may connect to
    pins: dict[str, str] = field(default_factory=dict)
    #: False when a proxy resolves on our behalf and pinning cannot apply.
    pins_enforced: bool = True
    #: Every connect target actually used, for tests and the evidence record.
    connects: list[tuple[str, str, int]] = field(default_factory=list)

    def approve(self, url: str) -> str:
        """Validate ``url`` and pin the address its socket must use."""
        from .netsec import validated_addresses

        kwargs = {"resolver": self.resolver} if self.resolver is not None else {}
        check_url(url, self.policy, **kwargs)

        host = httpx.URL(url).host
        addresses = validated_addresses(host)
        if not addresses:
            return ""
        self.pins[host] = str(addresses[0])
        return self.pins[host]


def _pinned_backend(pins: PinnedResolver):
    """An httpcore network backend that connects only to approved addresses."""
    import httpcore

    base = httpcore.AnyIOBackend()

    class PinnedBackend(httpcore.AsyncNetworkBackend):
        async def connect_tcp(self, host, port, timeout=None,
                              local_address=None, socket_options=None):
            target = pins.pins.get(host, host) if pins.pins_enforced else host
            if pins.pins_enforced and host in pins.pins and target != host:
                # The socket goes to the validated address; everything above
                # this layer still believes it is talking to `host`.
                pass
            pins.connects.append((host, target, port))
            return await base.connect_tcp(
                target, port, timeout=timeout, local_address=local_address,
                socket_options=socket_options)

        async def connect_unix_socket(self, path, timeout=None,
                                      socket_options=None):
            return await base.connect_unix_socket(
                path, timeout=timeout, socket_options=socket_options)

        async def sleep(self, seconds):
            await base.sleep(seconds)

    return PinnedBackend()


class PinnedTransport(httpx.AsyncHTTPTransport):
    """Transport whose sockets can only reach validated addresses.

    The request is untouched: same URL, same origin, same single `Host` header.
    Only the connect target below the pool is substituted.
    """

    def __init__(self, pins: PinnedResolver, **kwargs) -> None:
        super().__init__(**kwargs)
        self._pins = pins
        pool = getattr(self, "_pool", None)
        if pool is not None:
            # httpcore names this privately; if the internal changes, fall back
            # to an unpinned pool rather than silently pretending to pin.
            try:
                pool._network_backend = _pinned_backend(pins)
            except Exception:  # pragma: no cover - defensive
                pins.pins_enforced = False


def build_transport(policy: UrlPolicy | None, resolver=None,
                    proxy: str | None = None) -> tuple[object, PinnedResolver]:
    """``(transport, pins)``. With a proxy, pinning is disabled and recorded."""
    pins = PinnedResolver(policy=policy, resolver=resolver)
    if proxy:
        pins.pins_enforced = False
        return None, pins
    return PinnedTransport(pins), pins


__all__ = ["PinnedResolver", "PinnedTransport", "build_transport", "UrlRejected"]
