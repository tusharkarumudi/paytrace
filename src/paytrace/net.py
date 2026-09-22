"""Async HTTP layer: per-host token buckets, on-disk cache, request budget.

Caching is not a performance nicety here. Re-fetching a source changes what the
evidence record says was retrieved and when; for anything that may end up
supporting litigation, the cache is a performance store; the
evidence artifact is the hash-chained capture written by EvidenceLog.
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from .egress import Egress, EgressPool
from .netsec import UrlPolicy, UrlRejected
from .pinned import PinnedResolver, PinnedTransport

#: Requests per second, per host. Defaults are deliberately conservative.
RATE_LIMITS: dict[str, float] = {
    "efts.sec.gov": 8.0,
    "data.sec.gov": 8.0,
    "www.sec.gov": 8.0,
    "crt.sh": 1.0,
    "api.gleif.org": 4.0,
    "api.github.com": 8.0,
    "rdap.org": 5.0,
    "internetdb.shodan.io": 2.0,
    "api.mnemonic.no": 1.0,
    "keys.openpgp.org": 2.0,
    "_default": 2.0,
}


class BudgetExceeded(RuntimeError):
    pass


class _Bucket:
    def __init__(self, rate: float) -> None:
        self.rate = rate
        self.next_at = 0.0
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self.lock:
            now = time.monotonic()
            wait = max(0.0, self.next_at - now)
            self.next_at = max(now, self.next_at) + 1.0 / self.rate
        if wait:
            await asyncio.sleep(wait)


@dataclass
class Response:
    url: str
    status: int
    text: str
    from_cache: bool = False

    def json(self) -> Any:
        return json.loads(self.text)


#: The collector on whose behalf the current fetch is happening.
#:
#: A ContextVar rather than an attribute on Fetcher: collectors run
#: concurrently against one shared fetcher, so a mutable field would attribute
#: captures to whichever collector happened to set it last. Every capture
#: previously recorded collector="fetcher", which made the evidence package
#: unable to say what asked for anything.
CURRENT_COLLECTOR: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_collector", default="")


class collector_context:  # noqa: N801 - used as a context manager, not a type
    """Attribute captures made inside this block to a named collector.

        async with collector_context("gleif"):
            await fetcher.get(url)
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self._token = None

    def __enter__(self) -> collector_context:
        self._token = CURRENT_COLLECTOR.set(self.name)
        return self

    def __exit__(self, *exc) -> None:
        if self._token is not None:
            CURRENT_COLLECTOR.reset(self._token)

    async def __aenter__(self) -> collector_context:
        return self.__enter__()

    async def __aexit__(self, *exc) -> None:
        self.__exit__(*exc)


#: Headers whose VALUES are never recorded. The key is still recorded, so the
#: manifest shows that credentials were sent without disclosing them -- an
#: evidence package is built to be shared.
REDACTED_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "authentication",
})


def safe_headers(headers) -> dict[str, str]:
    """Header map with secret values replaced by a redaction marker.

    Names are kept because "an Authorization header was sent" is itself
    provenance a reviewer needs; values are dropped because the package is
    designed to be handed to someone else.
    """
    out: dict[str, str] = {}
    for key, value in dict(headers or {}).items():
        k = str(key).lower()
        out[k] = "<redacted>" if k in REDACTED_HEADERS else str(value)
    return out


class Fetcher:
    def __init__(
        self,
        user_agent: str,
        cache_dir: Path | None = None,
        max_requests: int = 5000,
        timeout: float = 20.0,
        url_policy: UrlPolicy | None = None,
        max_bytes: int = 10 * 1024 * 1024,
        egress: EgressPool | None = None,
        evidence_log=None,
        policy=None,
        resolver=None,
    ) -> None:
        # No CWD default. The cache holds retrieved bytes from the subject, so
        # writing it to whatever directory the process started in puts
        # investigation content outside the retention and minimisation boundary
        # the case file defines -- and leaves it there after the run.
        #
        # Callers that want a durable cache pass one (the runner puts it under
        # the case output). Callers that do not get a per-process temporary
        # directory.
        self._owns_cache = cache_dir is None
        if cache_dir is None:
            import tempfile
            cache_dir = Path(tempfile.mkdtemp(prefix="paytrace-cache-"))
        self.cache_dir = Path(cache_dir)
        # 0700. The cache holds retrieved subject content; on a shared host
        # the default 0755 exposed it to every local user.
        try:
            from attribution_graph.evidence import secure_mkdir
            secure_mkdir(self.cache_dir)
        except ImportError:
            self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_requests = max_requests
        self.count = 0
        self.max_bytes = max_bytes
        # SSRF guard. Every URL is validated before a connection is opened,
        # including redirect targets -- hosts here come from files the subject
        # of the investigation wrote.
        self.url_policy = url_policy or UrlPolicy()
        self.blocked: list[tuple[str, str]] = []
        # Content varies by the requester's apparent location, so the exit used
        # is part of the evidence rather than a transport detail. A capture
        # that does not record its egress is not reproducible even in
        # principle.
        self.egress = egress or EgressPool([Egress(label="direct")], "direct")
        # Capture recording is a transport invariant, not a caller
        # responsibility. The runner used to build an EvidenceLog, never pass
        # it anywhere, then write and self-verify it -- so a run that made real
        # HTTP requests produced an empty package with evidence_verified=True.
        # An empty package that verifies is a false assurance, not a missing
        # feature.
        self.evidence_log = evidence_log
        #: Consulted before every fetch when set. Constructing a PolicyEngine
        #: and never calling it meant `robots_policy: respect` in a case file
        #: bought nothing.
        self.policy = policy
        self.policy_decisions: list = []
        #: Guards against recursion: PolicyEngine fetches robots.txt through
        #: this same Fetcher, and evaluating policy for that request would
        #: re-enter the engine. The robots fetch still passes SSRF validation,
        #: the budget, egress selection and evidence capture -- it bypasses
        #: only the policy check.
        self._in_policy_lookup = False
        #: DNS resolver used by URL validation. Injectable so transport tests
        #: are deterministic -- mocking the HTTP transport was not enough,
        #: because validation still performed real DNS and returned None before
        #: the mock was ever reached. This is also the seam a future
        #: address-pinning fix for DNS rebinding will use.
        self.resolver = resolver
        #: Records the address each hostname was validated at, and pins the
        #: socket to it. Validating by name and then connecting by name is two
        #: independent resolutions; a subject-controlled name can answer
        #: differently for each. Every hop re-validates and re-pins.
        self.pins = PinnedResolver(policy=self.url_policy,
                                   resolver=self.resolver)
        self._timeout = timeout
        self._headers = {"User-Agent": user_agent,
                         "Accept": "application/json, text/html;q=0.9"}
        # One client per egress label, each bound to that egress's proxy.
        #
        # This used to be a single client with the EgressPool held beside it as
        # metadata, which meant the manifest recorded a vantage point the
        # transport never used. Recording provenance that did not happen is
        # worse than recording none: it is a fabricated chain of custody.
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._buckets: dict[str, _Bucket] = {}

    def client_for(self, label: str = "") -> httpx.AsyncClient:
        """The client bound to one egress. Built lazily, cached per label."""
        egress = self.egress.get(label)
        if egress.label not in self._clients:
            proxy = egress.proxy_url()          # raises if misconfigured
            if proxy:
                # The proxy resolves, so no address we validate is the address
                # the socket reaches. Recorded rather than assumed: a control
                # that cannot be enforced must not be reported as active.
                self.pins.pins_enforced = False
            self._clients[egress.label] = httpx.AsyncClient(
                timeout=self._timeout,
                # Redirects are followed manually so each hop can be
                # re-validated. A permitted host redirecting to
                # 169.254.169.254 defeats any check that only looks at the
                # first URL.
                follow_redirects=False,
                headers=self._headers,
                # httpx honours HTTP_PROXY/HTTPS_PROXY/ALL_PROXY by default, so
                # a "direct" egress could silently route through an ambient
                # proxy -- the manifest would record `direct` while the request
                # left via someone else's exit. Egress is declared in the case
                # file or it does not happen.
                trust_env=False,
                # Pinning is only possible when we resolve. Through a proxy the
                # proxy resolves, so it is disabled and recorded rather than
                # silently assumed -- see PinnedResolver.pins_enforced.
                **({"proxy": proxy} if proxy
                   else {"transport": PinnedTransport(self.pins)}),
            )
        return self._clients[egress.label]

    @property
    def _client(self) -> httpx.AsyncClient:
        """Default-egress client. Kept for callers that do not select one."""
        return self.client_for()

    def _bucket(self, host: str) -> _Bucket:
        if host not in self._buckets:
            self._buckets[host] = _Bucket(RATE_LIMITS.get(host, RATE_LIMITS["_default"]))
        return self._buckets[host]

    def _cache_path(self, url: str, headers: dict | None,
                    egress_label: str = "") -> Path:
        """Cache key. Includes the egress, because the same URL fetched from
        two countries is two different responses -- omitting it made a US
        capture serve a request that asked for a DE vantage point."""
        egress = self.egress.get(egress_label)
        key = hashlib.sha256(
            (url + json.dumps(headers or {}, sort_keys=True)
             + f"|egress={egress.label}|country={egress.country}").encode()
        ).hexdigest()
        return self.cache_dir / f"{key}.json"

    async def get(
        self,
        url: str,
        headers: dict | None = None,
        allow_html: bool = False,
        egress: str = "",
    ) -> Response | None:
        # Policy is evaluated BEFORE the cache is consulted. Serving a cached
        # body skipped the check entirely, so `robots_policy: respect` stopped
        # applying the moment a URL had been fetched once -- including by an
        # earlier run under a different policy.
        if self.policy is not None and not self._in_policy_lookup:
            decision = await self._evaluate_policy(url)
            if decision is None:
                # Evaluation failed. Under `respect` that must fail closed:
                # treating an unknown directive as permission is how a
                # respectful crawler quietly stops respecting anything.
                if getattr(self.policy, "policy", None) is not None and \
                        str(getattr(self.policy.policy, "value",
                                    self.policy.policy)) == "respect":
                    self.blocked.append(
                        (url, "fetch policy could not be evaluated; "
                              "`respect` fails closed"))
                    self._record_evidence(url, None, b"", egress,
                                          outcome="refused",
                                          note="policy evaluation failed under "
                                               "robots_policy: respect")
                    return None
            else:
                self.policy_decisions.append(decision)
                if not decision.should_fetch:
                    note = getattr(decision, "note", "") or "disallowed by policy"
                    self.blocked.append((url, f"fetch policy: {note}"))
                    self._record_evidence(url, None, b"", egress,
                                          outcome="refused", note=note)
                    return None

        cp = self._cache_path(url, headers, egress)
        if cp.exists():
            d = json.loads(cp.read_text())
            # A cache hit still has to appear in this run's evidence package.
            # Otherwise a second run consumed retrieved content and produced a
            # package with zero captures that verified clean -- the retrieval
            # happened, and the record of it lived in a different package.
            #
            # The entry is marked `cache` so a reviewer can see the bytes were
            # not fetched during this run, and carries the body so the digest
            # still commits to what was actually used.
            # Raw bytes, base64-encoded, so a cache hit records the digest of
            # what was actually served. Storing decoded text and re-encoding it
            # produced a different byte sequence -- and therefore a different
            # SHA-256 -- from the response the origin sent, which makes the
            # evidence record a claim about bytes that never existed.
            raw = base64.b64decode(d["body_b64"]) if "body_b64" in d \
                else (d.get("text") or "").encode()
            self._record_evidence(
                d.get("final_url", url), d.get("status"), raw, egress,
                request_headers=d.get("request_headers") or {},
                response_headers=d.get("response_headers") or {},
                outcome="cache",
                note=(f"served from the local HTTP cache; originally retrieved "
                      f"{d.get('requested_at', 'at an unrecorded time')} and "
                      f"not fetched during this run"))
            text = raw.decode(d.get("encoding") or "utf-8", errors="replace")
            return Response(d.get("final_url", url), d["status"], text,
                            from_cache=True)

        if self.count >= self.max_requests:
            raise BudgetExceeded(f"request budget of {self.max_requests} exhausted")

        try:
            self.pins.approve(url)
        except UrlRejected as e:
            self.blocked.append((url, e.reason))
            return None

        # Fetch policy.
        #
        # The real PolicyEngine.evaluate is `async (fetcher, url)` and its
        # FetchDecision exposes `note` and `should_fetch`, not `reason` and
        # `allowed`-as-veto. Calling it as `policy.evaluate(url)` raised
        # TypeError inside every collector, which Engine._process caught as an
        # ordinary collector error -- so a run finished with 0 claims, 0
        # captures and evidence_verified=True.
        #
        # `allowed` is what robots.txt says; `should_fetch` is what the
        # configured policy decides to do about it. Only the latter may veto:
        # under `record`, a disallowed path is fetched *and* recorded as
        # disallowed, which is the whole point of that mode.
        if self.policy is not None and not self._in_policy_lookup:
            decision = await self._evaluate_policy(url)
            if decision is not None:
                self.policy_decisions.append(decision)
                if not decision.should_fetch:
                    note = getattr(decision, "note", "") or "disallowed by policy"
                    self.blocked.append((url, f"fetch policy: {note}"))
                    self._record_evidence(url, None, b"", egress,
                                          outcome="refused", note=note)
                    return None

        result = await self._get_following_redirects(url, headers, egress=egress)
        if result is None:
            self._record_evidence(url, None, b"", egress, outcome="error",
                                  note="no response")
            return None
        status, raw, encoding, truncated, final_url, req_h, resp_h = result
        if status >= 400:
            # A 4xx/5xx is a physical response and part of the record. Returning
            # before recording meant an evidence package could show one request
            # and zero captures -- "checked and got nothing" is exactly what a
            # reviewer needs to distinguish from "never checked".
            # Attributed to the URL that produced the error, not to the one
            # the chain started from. The success path was corrected for this
            # and the error path was not, so a 302 -> 404 recorded the 404
            # against the original request URL and lost the resource that
            # actually returned it. Provenance has to identify the resource
            # behind every response, including unsuccessful ones.
            self._record_evidence(final_url, status, raw, egress,
                                  request_headers=req_h, response_headers=resp_h,
                                  outcome="error",
                                  note=f"HTTP {status}"
                                       + (f" after redirect from {url}"
                                          if final_url != url else ""))
            return Response(final_url, status, "")

        if truncated:
            self.blocked.append((url, f"body truncated at {self.max_bytes} bytes"))
        text = raw.decode(encoding or "utf-8", errors="replace")
        # 0600 for the same reason.
        cp.touch(mode=0o600, exist_ok=True)
        cp.write_text(json.dumps({
            "status": status,
            "body_b64": base64.b64encode(raw).decode(),
            "encoding": encoding,
            # The URL that actually served the body, so a later cache hit does
            # not attribute the response to the pre-redirect URL.
            "final_url": final_url,
            "requested_at": datetime.now(timezone.utc).isoformat(),
            # Persisted so a cache hit reproduces the original provenance
            # rather than silently presenting empty maps as if none were seen.
            "request_headers": req_h,
            "response_headers": resp_h,
        }))
        # Attributed to the URL that served it. The final 200 of a redirect
        # chain used to be recorded under the starting URL, so the manifest
        # said a body came from somewhere it did not.
        self._record_evidence(final_url, status, raw, egress,
                              request_headers=req_h, response_headers=resp_h,
                              outcome="success" if raw else "empty")
        return Response(final_url, status, text)

    async def _evaluate_policy(self, url: str):
        """Ask the policy engine, with robots retrieval exempted from policy."""
        self._in_policy_lookup = True
        try:
            with collector_context("fetch_policy"):
                return await self.policy.evaluate(self, url)
        except Exception as e:
            # A policy failure must not silently become "allowed": record it
            # and continue, but make it visible.
            self.blocked.append((url, f"policy evaluation failed: {e!r}"))
            return None
        finally:
            self._in_policy_lookup = False

    def _record_evidence(self, url, status, body, egress_label, *,
                         outcome="success", note="", collector="",
                         request_headers=None, response_headers=None):
        """Record a capture for every network attempt, including failures.

        Refusals and errors are recorded too: an evidence package that contains
        only successes cannot show what was tried and did not work, which is
        exactly what a reviewer needs to distinguish "not present" from "not
        checked".
        """
        if self.evidence_log is None:
            return
        try:
            self.evidence_log.record(
                url, status, body,
                collector=collector or CURRENT_COLLECTOR.get() or "fetcher",
                request_headers=request_headers or {},
                response_headers=response_headers or {},
                outcome=outcome, note=note,
                egress=self.egress.get(egress_label).label)
        except TypeError as e:
            # This used to fall back to an older signature, which quietly became
            # the normal path once `egress` was added -- every capture recorded
            # collector="fetcher" and egress="". A signature mismatch here is a
            # defect, not a compatibility case.
            raise RuntimeError(
                "EvidenceLog.record() rejected the capture arguments. This is a "
                "version mismatch between paytrace and attribution-graph, not a "
                "recoverable condition: silently dropping provenance would make "
                "the evidence package misleading."
            ) from e

    async def _read_capped(self, response) -> tuple[bytes, bool]:
        """Read a response body, stopping at ``max_bytes``.

        ``response.content`` materialises the entire body first, so a hostile
        endpoint could exhaust memory before any slice was applied -- the cap
        was documented but not implemented. Streaming stops reading at the
        limit, which is the only point at which the limit means anything.

        The cap applies to bytes *after* transfer decoding, so a decompression
        bomb is bounded by the same limit.
        """
        buf = bytearray()
        truncated = False
        async for chunk in response.aiter_bytes():
            remaining = self.max_bytes - len(buf)
            if remaining <= 0:
                truncated = True
                break
            buf.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
                break
        return bytes(buf), truncated

    async def _get_following_redirects(self, url: str, headers: dict | None,
                                       max_hops: int = 5, egress: str = ""):
        """Follow redirects manually, validating every hop.

        Returns ``(status, body, encoding, truncated)``.
        """
        seen: set[str] = set()
        for _ in range(max_hops):
            if url in seen:
                self.blocked.append((url, "redirect loop"))
                return None
            seen.add(url)

            # The budget is checked before every physical request, not once
            # per logical fetch. Checking only at entry let a redirect chain
            # run past max_requests: with max_requests=1, a 302 -> 200 sequence
            # completed with count=2.
            if self.count >= self.max_requests:
                self.blocked.append((url, "request budget exhausted mid-redirect"))
                raise BudgetExceeded(
                    f"request budget of {self.max_requests} exhausted during "
                    "redirect following")

            host = urlparse(url).netloc
            await self._bucket(host).acquire()
            self.count += 1
            client = self.client_for(egress)
            try:
                async with client.stream("GET", url, headers=headers) as r:
                    if r.status_code not in (301, 302, 303, 307, 308):
                        body, truncated = await self._read_capped(r)
                        return (r.status_code, body, r.encoding, truncated, url,
                                safe_headers(r.request.headers),
                                safe_headers(r.headers))
                    location = r.headers.get("location")
                    # Record the redirect itself: the chain is part of what
                    # happened, and only the final response was being captured.
                    # With headers. A redirect is a physical response and part
                    # of the chain's provenance -- it identifies the
                    # infrastructure transition -- so recording it without the
                    # metadata that identifies the hop was half a record.
                    self._record_evidence(
                        url, r.status_code, b"", egress, outcome="redirect",
                        request_headers=safe_headers(r.request.headers),
                        response_headers=safe_headers(r.headers),
                        note=f"-> {location}" if location else "no location header")
                    if not location:
                        return (r.status_code, b"", r.encoding, False, url,
                                safe_headers(r.request.headers),
                                safe_headers(r.headers))
            except httpx.HTTPError:
                return None

            url = str(httpx.URL(url).join(location))
            try:
                # A redirect is a new hostname and therefore a new resolution.
                self.pins.approve(url)
            except UrlRejected as e:
                self.blocked.append((url, f"redirect target rejected: {e.reason}"))
                return None
        self.blocked.append((url, "too many redirects"))
        return None

    async def get_json(self, url: str, headers: dict | None = None,
                       egress: str = "") -> Any | None:
        r = await self.get(url, headers, egress=egress)
        if not r or r.status != 200 or not r.text:
            return None
        try:
            return r.json()
        except json.JSONDecodeError:
            return None

    async def aclose(self) -> None:
        for c in self._clients.values():
            await c.aclose()
        self._clients.clear()
        # Remove a cache we created. Subject-retrieved content should not
        # outlive the process that fetched it.
        if getattr(self, "_owns_cache", False):
            import shutil
            shutil.rmtree(self.cache_dir, ignore_errors=True)
