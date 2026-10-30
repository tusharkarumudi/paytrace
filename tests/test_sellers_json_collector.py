"""`SellersJson.collect` -- the claim-building half of the payee pivot.

This collector is `priority = 1`, the highest-selectivity business pivot in the
toolkit: it is what turns `adsystem/seller_id` into a name, and in a real
investigation it is the step that names who gets paid. Its `collect` had **no
test coverage at all** -- the whole body, lines 195-249, never executed under
the suite -- which is how a dead `if True:` wrapper and an unreachable
`return []` survived in it.

`resolve_seller` is stubbed on purpose. The fetching, caching and streaming
fallback are covered in `test_sellersjson.py`; what was untested is everything
that happens to a record *after* it comes back, which is the part that decides
what evidence the case gets.
"""

import asyncio

from attribution_graph import Identifier, IdKind, Predicate, Reliability

from paytrace.collectors.business import SellersJson
from paytrace.sellersjson import SellerRecord

URL = "https://ads.example/sellers.json"


def _collect(monkeypatch, rec, value="ads.example/7"):
    """Drive the collector with one record and return its claims."""
    async def fake_resolve(fetcher, adsystem, seller_id, archive=False):
        return rec

    monkeypatch.setattr("paytrace.sellersjson.resolve_seller", fake_resolve)
    c = SellersJson(fetcher=object(), scope=object())
    return list(asyncio.run(c.collect(Identifier(IdKind.SELLER_ID, value))))


# ---- the shape of the identifier ------------------------------------------- #

def test_an_identifier_without_a_slash_yields_nothing(monkeypatch):
    """`adsystem/seller_id` is the contract; anything else is not for us."""
    assert _collect(monkeypatch, None, value="no-slash-here") == []


def test_an_unresolvable_seller_yields_nothing(monkeypatch):
    """Absent is not the same as unnamed, and neither is a claim."""
    assert _collect(monkeypatch, None) == []


# ---- the confidential branch ----------------------------------------------- #

def test_a_confidential_seller_yields_only_its_type(monkeypatch):
    """The publisher opted out of being named; the type still carries evidence.

    Emitting a name here would publish what the seller asked not to publish,
    and emitting nothing would throw away the one fact still on offer --
    whether the inventory is owned or resold.
    """
    rec = SellerRecord(adsystem="ads.example", seller_id="7", name="Hidden Ltd",
                       domain="hidden.example", seller_type="publisher",
                       is_confidential=True, source_url=URL)
    claims = _collect(monkeypatch, rec)
    assert len(claims) == 1
    (c,) = claims
    assert c.predicate is Predicate.SELLER_OF
    assert c.object == "PUBLISHER", "seller_type is upper-cased"
    assert c.reliability is Reliability.STRONG
    assert c.source_url == URL
    assert c.correlation_group == "sellers_json|ads.example|7"
    assert c.raw == {"is_confidential": 1}
    # The withheld fields must not appear anywhere in the emitted claim.
    assert "Hidden Ltd" not in str(c.object)
    assert all("Hidden Ltd" not in str(v) for v in (c.raw or {}).values())


# ---- the ordinary branch --------------------------------------------------- #

def test_an_organisation_seller_names_the_payee_and_its_domain(monkeypatch):
    rec = SellerRecord(adsystem="ads.example", seller_id="7",
                       name="Example Media Ltd", domain="example-media.test",
                       seller_type="PUBLISHER", source_url=URL)
    claims = _collect(monkeypatch, rec)
    assert len(claims) == 2
    name, operates = claims
    assert name.predicate is Predicate.LEGAL_NAME
    assert name.object == Identifier(IdKind.ORG_NAME, "Example Media Ltd")
    assert name.reliability is Reliability.STRONG
    assert name.raw["seller_type"] == "PUBLISHER"
    assert name.raw["declared_domain"] == "example-media.test"
    assert name.raw["sole_operator_pattern"] is False
    assert operates.predicate is Predicate.OPERATES
    assert operates.object == Identifier(IdKind.DOMAIN, "example-media.test")
    # One group, so two facts from one document cannot corroborate each other.
    assert name.correlation_group == operates.correlation_group
    assert name.correlation_group == "sellers_json|ads.example|7"


def test_a_personal_name_is_typed_as_a_person_not_an_organisation(monkeypatch):
    """A seller name is frequently a natural person.

    Typing every one as an organisation sends the investigation to corporate
    registries that will never hold a record for it.
    """
    rec = SellerRecord(adsystem="ads.example", seller_id="7",
                       name="John Smith", seller_type="PUBLISHER",
                       source_url=URL)
    (name,) = _collect(monkeypatch, rec)
    assert name.object == Identifier(IdKind.PERSON_NAME, "John Smith")
    assert name.raw["name_kind"] == "natural_person"
    # A named individual with no declared domain is usually the terminus.
    assert name.raw["sole_operator_pattern"] is True


def test_a_seller_with_no_name_still_yields_its_domain(monkeypatch):
    rec = SellerRecord(adsystem="ads.example", seller_id="7",
                       domain="example-media.test", seller_type="PUBLISHER",
                       source_url=URL)
    (operates,) = _collect(monkeypatch, rec)
    assert operates.predicate is Predicate.OPERATES


def test_a_seller_with_neither_name_nor_domain_yields_nothing(monkeypatch):
    """An empty record is not evidence of anything."""
    rec = SellerRecord(adsystem="ads.example", seller_id="7",
                       seller_type="INTERMEDIARY", source_url=URL)
    assert _collect(monkeypatch, rec) == []


def test_parent_object_contact_fields_are_never_emitted(monkeypatch):
    """`contact_email` on a sellers.json describes the AD SYSTEM, not the seller.

    Emitting it as seller evidence would attribute the ad system's own contact
    details to the publisher being investigated.
    """
    rec = SellerRecord(
        adsystem="ads.example", seller_id="7", name="Example Media Ltd",
        seller_type="PUBLISHER", source_url=URL,
        extra={"contact_email": "adops@ads.example",
               "contact_address": "1 Ad Street"})
    claims = _collect(monkeypatch, rec)
    blob = " ".join(str(c.object) + str(c.raw) for c in claims)
    assert "adops@ads.example" not in blob
    assert "1 Ad Street" not in blob


# ---- the refactor this file was written to protect ------------------------- #

def test_every_path_through_collect_is_exercised_here():
    """A guard on the test file, not the collector.

    These tests exist so that removing the dead `if True:` wrapper and its
    unreachable `return []` is provably behaviour-preserving. If `collect`
    grows a branch, this count stops matching and the new path needs a test
    rather than silently inheriting coverage from the old ones.
    """
    import ast
    import inspect
    import textwrap

    src = textwrap.dedent(inspect.getsource(SellersJson.collect))
    tree = ast.parse(src)
    returns = [n for n in ast.walk(tree) if isinstance(n, ast.Return)]
    assert len(returns) == 4, (
        f"collect has {len(returns)} return statements, not 4; a path was "
        "added or removed and the tests above may no longer cover them all")

    # The wrapper these tests were written to remove must not come back. It
    # went unnoticed for as long as it did because nothing here ran at all.
    consts = [n for n in ast.walk(tree)
              if isinstance(n, ast.If) and isinstance(n.test, ast.Constant)]
    assert not consts, "a constant-condition branch is back in collect"


# ---- the gate, so this class of defect cannot return silently -------------- #

def test_no_source_file_contains_unreachable_code():
    """Statements that can never run, and branches on a constant.

    `ruff` has no rule for this and `bandit` does not look, so a dead
    `if True:` wrapper sat in the highest-priority business collector across
    several releases. The reachability gate added earlier finds unused
    *definitions*; this finds unreachable *statements*, which is a different
    question and was the one nothing asked.
    """
    import ast
    import pathlib

    import paytrace

    def _const(node):
        return isinstance(node, ast.Constant) and not isinstance(
            node.value, str)

    def terminates(stmts):
        for s in stmts:
            if isinstance(s, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                return True
            if isinstance(s, ast.If):
                if _const(s.test):
                    branch = s.body if s.test.value else s.orelse
                    if terminates(branch):
                        return True
                elif s.orelse and terminates(s.body) and terminates(s.orelse):
                    return True
            if isinstance(s, ast.With) and terminates(s.body):
                return True
        return False

    root = pathlib.Path(paytrace.__file__).resolve().parent
    problems = []
    for f in sorted(root.rglob("*.py")):
        tree = ast.parse(f.read_text())
        rel = f.relative_to(root)
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and _const(node.test):
                problems.append(f"{rel}:{node.lineno}: branch on a constant")
            for field in ("body", "orelse", "finalbody"):
                stmts = getattr(node, field, None)
                if not isinstance(stmts, list):
                    continue
                for i, s in enumerate(stmts[:-1]):
                    if terminates([s]):
                        problems.append(
                            f"{rel}:{stmts[i + 1].lineno}: unreachable after "
                            f"{type(s).__name__} on line {s.lineno}")
                        break
    assert not problems, "unreachable code:\n  " + "\n  ".join(problems)
