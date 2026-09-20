# Security policy

## Reporting a vulnerability

Report privately via GitHub Security Advisories ("Report a vulnerability" on the
Security tab). Please do not open a public issue for security matters.

Expect an acknowledgement within 5 working days.

## Scope

In scope:

- Code execution via crafted ads.txt, sellers.json or registry API responses
- SQL injection in the corpus index
- SSRF via crafted domain or ad-system values reaching the fetcher
- Cache poisoning in the on-disk response cache
- Bypass of the source-class deny list

Out of scope:

- Misuse of the library for investigations the operator was not authorized to
  conduct. Scope enforcement here is a guardrail against accident and drift, not
  a security boundary against a determined operator who controls the code.
- Vulnerabilities in `attribution-graph` — report those to that repository.

## Residual security posture (authoritative)

This section is the single source of truth. `DEPLOYMENT.md` and `PUBLISHING.md`
link here rather than restating it, because three files describing the same
posture in slightly different words is how a reviewer ends up trusting the
wrong one.

**DNS rebinding — closed for direct egress.** Pinning happens at the socket
layer: `connect_tcp` receives only an address that passed validation, while the
request URL, the connection-pool origin, TLS SNI, certificate verification and
a single `Host` header all keep the original hostname. Connections are never
reused across different logical hostnames. Every redirect hop re-validates and
re-pins.

**Not closed through a proxy.** When egress goes through a proxy, the proxy
resolves and no address we validate is the address the socket reaches.
`pins_enforced` is set to `false` on that pool and recorded in the run. Rely on
the proxy's own egress policy, and deny private ranges at the network layer.

**Not closed for the screenshot path.** `ScreenshotCapturer` navigates with a
browser whose subresource requests do not pass through the URL policy. This is
why `attribution run --screenshots` exits 2. Do not point it at an untrusted
target from a host with internal network access.

**Filesystem.** Case output, evidence, captures, cache and the audit trail are
created 0700/0600, and pre-existing paths are tightened rather than trusted.

**Still recommended regardless:** run as a dedicated unprivileged account with
no cloud instance role, and deny egress to RFC1918, link-local, ULA and
169.254.169.254 at the network layer. Defence in depth is not the same as a
single control.

## Scope of `minimize: true`

In scope, and treated as a vulnerability if violated: an unminimised identifier
in any **derived** artifact — the graph, FTM, Cypher, either report, or the
audit log — in any form this toolkit produces.

Explicitly out of scope: `evidence/captures/*.bin`, the URLs in
`evidence_manifest.json`, and the HTTP cache. Those preserve the bytes that
were served and the requests that obtained them; redacting them would break the
digests they exist to support. **An evidence package is not made safe to share
by this setting.**

Reports of unminimised identifiers in derived output are security reports.
Reports that preserved evidence contains subject data are working as designed.


## Design note

`AttributionGraph` and `Claim` objects deserialized from untrusted JSON should
be treated as untrusted input. The library does not currently sandbox claim
`raw` payloads.
