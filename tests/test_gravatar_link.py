"""Binding observed emails to observed avatar hashes, by arithmetic.

The link was impossible before: the collector hashed emails with SHA-256 while
every hash published in page markup is MD5, so an email and a page's hash for
the same person could never match. And establishing it by asking gravatar.com
about each discovered address is a request per address to answer a question
md5 answers for free.
"""

from attribution_graph import (
    AttributionGraph,
    Claim,
    Identifier,
    IdKind,
    Predicate,
    Reliability,
)

from paytrace.fingerprint import gravatar_hash
from paytrace.gravatar_link import link_gravatars

ADDRESS = "jane@operator-site.example"
DIGEST = gravatar_hash(ADDRESS)


def _graph(*, email=ADDRESS, digest=DIGEST, group="surface|site.example",
           source="https://site.example/about"):
    g = AttributionGraph(case_ref="GRAV")
    if digest:
        g.add_claim(Claim(
            subject=Identifier(IdKind.DOMAIN, "site.example"),
            predicate=Predicate.SHARES_GRAVATAR,
            object=Identifier(IdKind.GRAVATAR_HASH, digest),
            collector="deep_artifacts", source_url=source,
            reliability=Reliability.STRONG,
            correlation_group=group))
    if email:
        g.add_claim(Claim(
            subject=Identifier(IdKind.DOMAIN, "site.example"),
            predicate=Predicate.PROFILE_BINDING,
            object=Identifier(IdKind.EMAIL, email),
            collector="imprint", source_url="https://site.example/imprint",
            reliability=Reliability.STRONG,
            correlation_group="imprint|site.example"))
    return g


def test_the_hash_matches_what_pages_actually_publish():
    """MD5 of the lowercased, trimmed address. Not SHA-256."""
    import hashlib

    assert hashlib.md5(ADDRESS.encode()).hexdigest() == DIGEST  # noqa: S324
    assert len(DIGEST) == 32
    assert gravatar_hash("  JANE@Operator-Site.Example ") == DIGEST


def test_an_observed_email_is_bound_to_an_observed_hash():
    r = link_gravatars(_graph())
    assert r.matched == [(ADDRESS, DIGEST)]
    assert len(r.claims) == 1
    c = r.claims[0]
    assert c.subject.kind is IdKind.GRAVATAR_HASH
    assert c.object.kind is IdKind.EMAIL
    assert c.collector == "gravatar_link"


def test_it_makes_no_requests():
    """The whole point: the binding is arithmetic over values already held."""
    r = link_gravatars(_graph())
    assert r.requests == 0
    assert "no requests" in r.summary()


def test_the_binding_cannot_corroborate_itself():
    """A computed restatement of an observed value is the same fact as the
    observation. Given its own group it would turn one page into two
    independent sources."""
    r = link_gravatars(_graph(group="surface|site.example"))
    assert r.claims[0].correlation_group == "surface|site.example"


def test_the_binding_is_not_definitional():
    """md5(email) == hash says the page displays that address's avatar. It
    does not say the page's operator controls the address -- anyone who knows
    an address can embed its hash, which is how you implicate someone. A
    planted hash must not bind a victim."""
    from attribution_graph.scoring import is_definitional

    c = link_gravatars(_graph()).claims[0]
    assert not is_definitional(c), \
        "a hash on a subject-controlled page must not bypass corroboration"

    from attribution_graph.scoring import DEFINITIONAL_COLLECTORS
    assert "gravatar_link" not in DEFINITIONAL_COLLECTORS, \
        "the carve-out is for registries that ISSUE an identifier"


def test_the_caveat_travels_with_the_claim():
    c = link_gravatars(_graph()).claims[0]
    assert "does not follow" in c.raw["caveat"]
    assert c.raw["requests"] == 0


def test_a_non_matching_email_is_not_bound():
    r = link_gravatars(_graph(email="someone-else@other.example"))
    assert r.matched == []
    assert r.claims == []
    assert "no match" in r.summary()


def test_nothing_is_invented_to_test():
    """No candidate address is generated. A guess, hashed and matched, would
    manufacture a binding and present it with the certainty of arithmetic."""
    import inspect

    from paytrace import gravatar_link

    src = inspect.getsource(gravatar_link)
    for forbidden in ("itertools", "product(", "permutations", "for first in",
                      "@" + "{", "f\"{name}@"):
        assert forbidden not in src, f"candidate generation: {forbidden}"


def test_only_observed_values_are_compared():
    g = _graph(email=None)
    r = link_gravatars(g)
    assert r.hashes == 1 and r.emails == 0
    assert r.matched == []
    assert "nothing to compare" in r.summary()


def test_a_malformed_hash_is_ignored():
    r = link_gravatars(_graph(digest="not-a-hash"))
    assert r.hashes == 0


def test_the_collector_and_the_linker_agree_on_the_algorithm():
    """They disagreed for several releases, which is why the link never
    happened in any real run."""
    import inspect

    from paytrace.collectors import persona

    src = inspect.getsource(persona.Gravatar.collect)
    assert "sha256" not in src.lower(), "the collector is back on SHA-256"
    assert "gravatar_hash" in src
