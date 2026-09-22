"""Web surface harvesting.

The pivot this completes: the seed domain often holds nothing, but a sibling the
operator forgot to harden holds a name, a login, or a leaked .env. Every test
here is a signal that would identify an operator who thought they were anonymous.
"""

from attribution_graph import IdKind, Predicate, Reliability

from paytrace.collectors import registry


class _Fetcher:
    def __init__(self, routes, headers=None):
        self.routes = routes
        self.hdrs = headers or {}
        self.requests = []

    async def get(self, url, headers=None, allow_html=False):
        self.requests.append(url)
        body = self.routes.get(url)
        hdrs = self.hdrs

        class R:
            status = 200 if body is not None else 404
            text = body or ""
            headers = hdrs
        return R()


class _Scope:
    case_ref = "T"
    authorization = "t"

    def audit(self, *a, **k):
        pass


def _harvest(routes, headers=None, domain="target.example"):
    from attribution_graph import Identifier
    c = registry()["surface_harvest"](_Fetcher(routes, headers), _Scope())
    import asyncio
    return list(asyncio.run(c.collect(Identifier(IdKind.DOMAIN, domain))))


def _objs(claims, kind):
    return {c.object.value for c in claims if c.object.kind is kind}


# ---- it runs on any domain, which is the whole point ----------------------- #

def test_registered_and_accepts_domains():
    c = registry()["surface_harvest"]
    assert IdKind.DOMAIN in c.accepts


# ---- HTML body ------------------------------------------------------------- #

def test_mailto_and_body_emails():
    html = ('<a href="mailto:ops@target.example">mail</a> '
            'contact billing@target.example')
    emails = _objs(_harvest({"https://target.example/": html}), IdKind.EMAIL)
    assert "ops@target.example" in emails
    assert "billing@target.example" in emails


def test_email_in_html_comment_is_flagged_as_a_leftover():
    html = "<!-- TODO email dev@realname.example before launch -->"
    claims = _harvest({"https://target.example/": html})
    dev = [c for c in claims if c.object.value == "dev@realname.example"]
    assert dev and "developer leftover" in dev[0].raw.get("note", "")


def test_meta_author_and_byline_yield_person_names():
    html = ('<meta name="author" content="Tran Thi Binh">'
            '<p>Written by Jane Roberts</p>')
    names = _objs(_harvest({"https://target.example/": html}), IdKind.PERSON_NAME)
    assert "Tran Thi Binh" in names
    assert "Jane Roberts" in names


def test_generic_bylines_are_rejected():
    html = '<meta name="author" content="admin"><p>posted by the editor</p>'
    assert not _objs(_harvest({"https://target.example/": html}), IdKind.PERSON_NAME)


def test_wordpress_author_slug_leaks_the_login():
    html = '<a href="/author/tranbinh/">posts</a>'
    handles = _objs(_harvest({"https://target.example/": html}), IdKind.HANDLE)
    assert "wp:tranbinh" in handles


def test_gravatar_hash_captured():
    html = '<img src="https://gravatar.com/avatar/0123456789abcdef0123456789abcdef">'
    assert "0123456789abcdef0123456789abcdef" in _objs(
        _harvest({"https://target.example/": html}), IdKind.GRAVATAR_HASH)


def test_google_docs_link_captured():
    html = '<a href="https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz">doc</a>'
    urls = _objs(_harvest({"https://target.example/": html}), IdKind.URL)
    assert any(u.startswith("gdoc:") for u in urls)


def test_service_ids_cluster_the_estate():
    html = '<script>var disqus_shortname="krakenmedia";</script> krakenmedia.disqus.com'
    sids = _objs(_harvest({"https://target.example/": html}), IdKind.SERVICE_ID)
    assert "disqus:krakenmedia" in sids


def test_service_id_is_a_strong_shared_signal():
    html = "krakenmedia.disqus.com"
    claims = _harvest({"https://target.example/": html})
    svc = [c for c in claims if c.object.kind is IdKind.SERVICE_ID]
    assert svc and svc[0].reliability is Reliability.STRONG
    assert svc[0].predicate is Predicate.SHARES_ANALYTICS_ID


# ---- headers --------------------------------------------------------------- #

def test_header_fingerprint_clusters_but_does_not_identify():
    claims = _harvest(
        {"https://target.example/": "<html></html>"},
        headers={"Server": "nginx/1.24", "X-Powered-By": "PHP/8.2"})
    fp = [c for c in claims if c.object.value.startswith("stackfp:")]
    assert fp
    assert fp[0].reliability is Reliability.WEAK
    assert "does not identify an operator" in fp[0].raw["note"]


# ---- exposed paths: the jackpot -------------------------------------------- #

def test_exposed_env_yields_operator_email():
    env = ("APP_NAME=KrakenMedia\n"
           "MAIL_FROM_ADDRESS=admin@krakenreal.example\n"
           "MAIL_FROM_NAME=Kraken Operator\n"
           "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    claims = _harvest({
        "https://target.example/": "<html></html>",
        "https://target.example/.env": env})
    emails = _objs(claims, IdKind.EMAIL)
    assert "admin@krakenreal.example" in emails
    env_email = [c for c in claims if c.object.value == "admin@krakenreal.example"]
    assert env_email[0].reliability is Reliability.STRONG
    assert env_email[0].predicate is Predicate.REGISTRANT


def test_exposed_env_flags_credentials_without_storing_them():
    """Secrets present are flagged, never recorded as values."""
    env = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    claims = _harvest({
        "https://target.example/": "<html></html>",
        "https://target.example/.env": env})
    leak = [c for c in claims if c.object.value.startswith("leak:env/")]
    assert leak and "not recorded" in leak[0].raw["note"]
    assert "wJalr" not in repr([c.to_dict() for c in claims])


def test_exposed_git_config_reveals_the_account():
    git = "[core]\n[remote \"origin\"]\n\turl = git@github.com:krakenops/site.git\n"
    claims = _harvest({
        "https://target.example/": "<html></html>",
        "https://target.example/.git/config": git})
    handles = _objs(claims, IdKind.HANDLE)
    assert "git:krakenops" in handles


def test_wp_rest_users_endpoint_yields_login_names():
    users = '[{"slug":"tranbinh","name":"Tran Thi Binh"}]'
    claims = _harvest({
        "https://target.example/": "<html></html>",
        "https://target.example/wp-json/wp/v2/users": users})
    assert "wp:tranbinh" in _objs(claims, IdKind.HANDLE)
    assert "Tran Thi Binh" in _objs(claims, IdKind.PERSON_NAME)


def test_webfinger_yields_federated_identity():
    wf = '{"subject":"acct:binh@target.example","links":[]}'
    claims = _harvest({
        "https://target.example/": "<html></html>",
        "https://target.example/.well-known/webfinger": wf})
    assert "binh@target.example" in _objs(claims, IdKind.EMAIL)


def test_only_a_fixed_path_set_is_probed_never_enumeration():
    """The line the collector will not cross: a fixed conventional set, never a
    generated wordlist."""
    f_routes = {"https://target.example/": "<html></html>"}
    import asyncio

    from attribution_graph import Identifier
    fetcher = _Fetcher(f_routes)
    c = registry()["surface_harvest"](fetcher, _Scope())
    asyncio.run(c.collect(Identifier(IdKind.DOMAIN, "target.example")))
    probed = [u for u in fetcher.requests if u != "https://target.example/"]
    assert len(probed) <= 10, "must be a small fixed set, not enumeration"


def test_missing_surface_yields_nothing_quietly():
    assert _harvest({"https://target.example/": "<html>nothing</html>"}) == []


# ---- the pivot scenario ---------------------------------------------------- #

def test_sibling_domain_carries_the_answer_the_seed_lacked():
    """The scenario: seed is clean, a sibling leaks the operator.

    The seed's homepage has only a privacy-proxied contact. The sibling — reached
    because it shares an analytics ID — exposes a .env with the real address.
    """
    seed = _harvest({"https://seed.example/": "<p>contact us via the form</p>"},
                    domain="seed.example")
    assert not _objs(seed, IdKind.EMAIL)

    sibling = _harvest({
        "https://sibling.example/": "<html></html>",
        "https://sibling.example/.env": "MAIL_FROM_ADDRESS=real@operator.example\n"},
        domain="sibling.example")
    assert "real@operator.example" in _objs(sibling, IdKind.EMAIL)
