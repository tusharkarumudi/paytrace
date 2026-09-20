"""ads.txt account classification.

The problem these encode: networks hand publishers a block of lines to paste, so
a DIRECT label may describe the publisher's account, the network's, or a
partner's two layers up. The same seller IDs then appear on tens of thousands of
unrelated domains, and two sites that pasted the same block look identical.
"""

import pytest

from paytrace.adstxt import (
    BOILERPLATE_THRESHOLD,
    AccountClass,
    classify_account,
    compare_domains,
    key_accounts,
    parse,
)

# A realistic file: two real accounts buried in pasted network blocks.
REAL = """# Publisher ads.txt
OWNERDOMAIN=examplemedia.example
CONTACT=ops@examplemedia.example # billing only
pubmatic.example, 156423, DIRECT, 5d62403b186f2ace
adx.example, pub-1234567890123456, DIRECT, f08c47fec0942fa0
"""
BOILERPLATE = "\n".join(
    f"network{i}.example, {100000 + i}, RESELLER, cert{i}" for i in range(300))

FILE_A = REAL + "\n" + BOILERPLATE
FILE_B = ("OWNERDOMAIN=other.example\n"
          "othernet.example, 999, DIRECT\n" + BOILERPLATE)


def holders(adsystem, seller_id):
    """156423 is a real account; the network block is everywhere."""
    if adsystem.startswith("network"):
        return 40_000
    if (adsystem, seller_id) == ("pubmatic.example", "156423"):
        return 3
    if (adsystem, seller_id) == ("adx.example", "pub-1234567890123456"):
        return 2
    return 5


# ---- parsing --------------------------------------------------------------- #

def test_parses_variables_comments_and_cid():
    a = parse(REAL, "examplemedia.example")
    assert a.owner_domain == "examplemedia.example"
    assert a.variable_comments["CONTACT"] == "billing only"
    assert a.accounts[0].cid == "5d62403b186f2ace"
    assert a.standalone_comments


def test_wellknown_style_stats():
    a = parse(FILE_A, "a.example")
    assert a.record_count == 302
    assert a.direct_count == 2
    assert a.reseller_count == 300
    assert a.system_count == 302
    assert a.looks_aggregated


def test_placeholder_records_are_flagged_and_skipped():
    a = parse("placeholder.example, placeholder, DIRECT, placeholder\n", "x")
    assert a.has_placeholder
    assert a.accounts == []


def test_relationship_other_than_direct_or_reseller_is_ignored():
    assert parse("net.example, 1, SOMETHING\n", "x").accounts == []


# ---- the core problem ------------------------------------------------------ #

def test_direct_alone_is_not_evidence():
    """A DIRECT line on 40,000 domains is a pasted template, not a relationship."""
    from paytrace.adstxt import Account
    a = classify_account(Account("network0.example", "100000", "DIRECT"),
                         holders=40_000)
    assert a.klass is AccountClass.BOILERPLATE
    assert a.weight == 0.0
    assert "template" in " ".join(a.reasons)


def test_rare_direct_reciprocated_is_a_publisher_account():
    from paytrace.adstxt import Account
    a = classify_account(Account("pubmatic.example", "156423", "DIRECT"),
                         holders=3, reciprocated=True, seller_type="PUBLISHER",
                         seller_domain="examplemedia.example",
                         owner_domain="examplemedia.example")
    assert a.klass is AccountClass.PUBLISHER
    assert a.discriminating and a.weight == 1.0


def test_unreciprocated_direct_is_downgraded():
    """sellers.json not naming the domain means the label may be copied."""
    from paytrace.adstxt import Account
    a = classify_account(Account("pubmatic.example", "156423", "DIRECT"),
                         holders=3, reciprocated=False)
    assert a.klass is AccountClass.RESELLER_CHAIN
    assert not a.discriminating
    assert "unreciprocated" in " ".join(a.reasons)


def test_no_corpus_means_unknown_not_optimistic():
    from paytrace.adstxt import Account
    a = classify_account(Account("x.example", "1", "DIRECT"), holders=None)
    assert a.klass is AccountClass.UNKNOWN
    assert "no corpus" in " ".join(a.reasons)


def test_reseller_records_describe_a_supply_path_not_ownership():
    from paytrace.adstxt import Account
    a = classify_account(Account("x.example", "1", "RESELLER"), holders=2)
    assert a.klass is AccountClass.RESELLER_CHAIN


# ---- finding the one-to-five key accounts ---------------------------------- #

def test_key_accounts_reduces_hundreds_to_a_handful():
    k = key_accounts(parse(FILE_A, "a.example"), holders)
    assert k.total == 302
    assert k.boilerplate_count == 300
    assert len(k.discriminating) == 2
    assert {a.account.seller_id for a in k.discriminating} == {
        "156423", "pub-1234567890123456"}


def test_key_accounts_sorted_rarest_first():
    k = key_accounts(parse(FILE_A, "a.example"), holders)
    assert k.discriminating[0].holders <= k.discriminating[-1].holders


def test_key_accounts_notes_aggregation_and_ownerdomain():
    k = key_accounts(parse(FILE_A, "a.example"), holders)
    joined = " ".join(k.notes)
    assert "aggregates network templates" in joined
    assert "OWNERDOMAIN" in joined


def test_file_with_only_boilerplate_yields_nothing():
    k = key_accounts(parse(BOILERPLATE, "b.example"), holders)
    assert not k.discriminating
    assert "declares nothing" in k.render()


# ---- template sharing vs common control ------------------------------------ #

def test_large_overlap_from_a_shared_template_is_not_evidence():
    """The false positive this whole module exists to prevent."""
    o = compare_domains(parse(FILE_A, "a.example"), parse(FILE_B, "b.example"),
                        holders)
    assert o.shared_total == 300
    assert o.shared_rare == 0
    assert o.is_template_sharing
    assert not o.is_operator_signal
    assert "collapses to nothing" in o.render()


def test_shared_rare_account_is_an_operator_signal():
    other = REAL.replace("OWNERDOMAIN=examplemedia.example", "OWNERDOMAIN=x.example")
    o = compare_domains(parse(FILE_A, "a.example"), parse(other, "c.example"),
                        holders)
    assert o.shared_rare == 2
    assert o.is_operator_signal
    assert not o.is_template_sharing


def test_identical_files_are_flagged_as_the_same_template():
    o = compare_domains(parse(FILE_A, "a.example"), parse(FILE_A, "b.example"),
                        holders)
    assert o.same_fingerprint
    assert "IDENTICAL FILE" in o.render()


def test_jaccard_on_rare_accounts_separates_the_cases():
    template = compare_domains(parse(FILE_A, "a"), parse(FILE_B, "b"), holders)
    assert template.jaccard_all > 0.9      # looks identical
    assert template.jaccard_rare == 0.0    # is not


def test_fingerprint_is_stable_and_order_independent():
    a = parse("x.example, 1, DIRECT\ny.example, 2, DIRECT\n", "d")
    b = parse("y.example, 2, DIRECT\nx.example, 1, DIRECT\n", "d")
    assert a.template_fingerprint() == b.template_fingerprint()


@pytest.mark.parametrize("count,expected", [
    (BOILERPLATE_THRESHOLD + 1, AccountClass.BOILERPLATE),
    (BOILERPLATE_THRESHOLD, AccountClass.LIKELY_OWNED),
])
def test_boilerplate_threshold_boundary(count, expected):
    from paytrace.adstxt import Account
    a = classify_account(Account("x.example", "1", "DIRECT"), holders=count)
    if expected is AccountClass.BOILERPLATE:
        assert a.klass is expected
    else:
        assert a.klass in (AccountClass.LIKELY_OWNED, AccountClass.RESELLER_CHAIN)
