"""`paytrace` command-line behaviour on a real network.

Mock transports hold no real connections, so they cannot show bugs that only
appear when a client belongs to an event loop. These tests use a transport
that behaves like a real connection pool.
"""

import asyncio

import httpx


class _LoopBoundTransport(httpx.AsyncBaseTransport):
    """Behaves like a real connection pool: it belongs to the event loop that
    first used it, and cannot be closed from another. httpx.MockTransport has
    no such state, which is why a second asyncio.run() for cleanup passed every
    mocked test and crashed on every real network."""

    def __init__(self, handler):
        self._handler, self._loop = handler, None

    async def handle_async_request(self, request):
        self._loop = self._loop or asyncio.get_running_loop()
        return self._handler(request)

    async def aclose(self):
        if self._loop is not None and asyncio.get_running_loop() is not self._loop:
            raise RuntimeError("Event loop is closed")


def _real_world(monkeypatch):
    import paytrace.net as net

    def handler(req):
        if req.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nAllow: /\n")
        if req.url.path == "/ads.txt":
            return httpx.Response(200, text="adnet.example, 7741, DIRECT\n")
        return httpx.Response(404)

    original = net.Fetcher.__init__

    def patched(self, *a, **k):
        k["resolver"] = lambda host: ["93.184.216.34"]
        original(self, *a, **k)
        for route in self.egress.egresses:
            self._clients[route.label] = httpx.AsyncClient(
                transport=_LoopBoundTransport(handler), follow_redirects=False)

    monkeypatch.setattr(net.Fetcher, "__init__", patched)


def _case(tmp_path):
    p = tmp_path / "case.yaml"
    p.write_text("case_ref: T\nauthorization: test\ncontact_email: t@example.com\n"
                 "seeds: [domain:live-site.example]\nentity_types_allowed: [Company]\n"
                 f"audit_path: {tmp_path}/audit.jsonl\nrobots_policy: respect\nmax_requests: 20\n")
    return p


def test_paytrace_run_closes_the_fetcher_in_the_loop_that_used_it(monkeypatch, tmp_path):
    """`paytrace run` closed its fetcher in a second asyncio.run() and crashed
    with "Event loop is closed" on every real network."""
    from paytrace.cli import main

    _real_world(monkeypatch)
    assert main(["run", "--case", str(_case(tmp_path)), "--out", str(tmp_path / "out")]) == 0
