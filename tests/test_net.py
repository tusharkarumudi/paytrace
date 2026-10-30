

def test_an_unreadable_ca_bundle_is_treated_as_absent(tmp_path, monkeypatch):
    """`is_file()` stats; OpenSSL opens.

    A CA path we can stat but not read passed the check and then raised
    PermissionError out of `load_verify_locations` -- which happens during
    client construction, so every retrieval in the run died rather than one
    host failing. This code exists for sandboxes, and a sandbox that exports
    SSL_CERT_FILE pointing into another user's home while the tool runs
    unprivileged produces exactly that. Found by running the suite as a
    non-root user; as root the file was readable and the bug invisible.

    A bundle we cannot read is a bundle we do not have.
    """
    import os

    from paytrace.net import Fetcher

    # The container running these tests may already export one of the others;
    # without clearing them the fall-through makes the assertions meaningless.
    for var in Fetcher._CA_VARS:
        monkeypatch.delenv(var, raising=False)

    good = tmp_path / "ca.crt"
    good.write_text("-----BEGIN CERTIFICATE-----\n")
    f = Fetcher(user_agent="t")
    egress = type("E", (), {"provider": "environment", "label": "env"})()

    monkeypatch.setenv("SSL_CERT_FILE", str(good))
    assert f._trust_store(egress) == str(good), "a readable bundle was skipped"
    assert f.tls_intercepted == "SSL_CERT_FILE", "interception not recorded"

    # Unreadable: stat succeeds, open does not.
    bad = tmp_path / "locked.crt"
    bad.write_text("-----BEGIN CERTIFICATE-----\n")
    bad.chmod(0o000)
    if os.access(bad, os.R_OK):          # running as root: chmod cannot deny us
        import pytest
        pytest.skip("cannot make a file unreadable as this user")
    f2 = Fetcher(user_agent="t")
    monkeypatch.setenv("SSL_CERT_FILE", str(bad))
    assert f2._trust_store(egress) == "", "an unreadable bundle was returned"
    assert not f2.tls_intercepted, "interception claimed for a bundle never read"


def test_a_missing_ca_bundle_does_not_claim_interception(tmp_path, monkeypatch):
    """The same for a path that is simply not there."""
    from paytrace.net import Fetcher

    f = Fetcher(user_agent="t")
    egress = type("E", (), {"provider": "environment", "label": "env"})()
    for var in Fetcher._CA_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "nope.crt"))
    assert f._trust_store(egress) == ""
    assert not f.tls_intercepted


def test_the_pinned_transport_does_not_take_ca_trust_from_the_environment(
        tmp_path, monkeypatch):
    """`trust_env=False` on the client does not reach the transport.

    An `httpx.AsyncHTTPTransport` built with no arguments defaults to
    `trust_env=True` and reads SSL_CERT_FILE / REQUESTS_CA_BUNDLE itself when
    it builds its SSL context. `PinnedTransport(self.pins)` was built exactly
    that way, so on the pinned (non-proxy) path the environment could add CA
    trust to a `direct` egress -- the precise thing `_trust_store` refuses to
    allow, because it lets whoever set the variable choose who we believe.

    The client's own `trust_env=False` carried a comment explaining why ambient
    environment settings must not apply to a declared egress. The transport
    below it quietly did the opposite.
    """
    import contextlib

    import httpx

    captured = {}
    real_init = httpx.AsyncHTTPTransport.__init__

    def spy(self, *a, **kw):
        captured.update(kw)
        return real_init(self, *a, **kw)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "__init__", spy)
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "attacker.crt"))

    from paytrace.net import Fetcher

    f = Fetcher(user_agent="t")
    # `client_for` takes a LABEL, and a Fetcher always has a `direct` egress.
    with contextlib.suppress(Exception):   # construction varies by httpx version
        f.client_for("direct")
    assert captured, "the transport was never constructed; the test is not "\
                     "exercising the path it claims to"
    assert captured.get("trust_env") is False, (
        "the pinned transport reads CA trust from the environment")


def test_a_bare_pinned_transport_still_refuses_environment_trust(monkeypatch):
    """The safe default lives in the class, not only at the one call site.

    `net.py` passing `trust_env=False` fixes the path it controls. Anything
    else constructing `PinnedTransport(pins)` -- tests do, and so would the
    next caller -- would get httpx's default of True and read
    SSL_CERT_FILE / REQUESTS_CA_BUNDLE again. An invariant that holds only
    where somebody remembered to restate it is not an invariant.
    """
    import httpx

    from paytrace.pinned import PinnedResolver, PinnedTransport

    captured = {}
    real_init = httpx.AsyncHTTPTransport.__init__

    def spy(self, *a, **kw):
        captured.update(kw)
        return real_init(self, *a, **kw)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "__init__", spy)
    PinnedTransport(PinnedResolver())
    assert captured.get("trust_env") is False

    # An explicit caller can still opt in; the default is a default.
    #
    # Construction is allowed to fail here: opting in means httpx really does
    # read SSL_CERT_FILE, and on a machine where that points somewhere this
    # user cannot read -- which is exactly the condition that uncovered all of
    # this -- it raises. What is under test is the value that reaches the
    # transport, which the spy has already recorded by then.
    import contextlib

    captured.clear()
    with contextlib.suppress(OSError):
        PinnedTransport(PinnedResolver(), trust_env=True)
    assert captured.get("trust_env") is True
