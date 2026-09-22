"""Tests for the reverse ads.txt index and its role as a selectivity corpus."""

from datetime import datetime, timezone

import pytest
from attribution_graph import Identifier, IdKind

from paytrace.index import AdsTxtIndex

NOW = datetime.now(timezone.utc).isoformat()


@pytest.fixture
def idx(tmp_path):
    ix = AdsTxtIndex(str(tmp_path / "t.sqlite"))
    # (domain, adsystem, seller_id, relationship, cid, resource, fetched_at)
    rows = [
        ("a.example", "pubmatic.com", "156423", "DIRECT", "cert1", "ads_txt", NOW),
        ("b.example", "pubmatic.com", "156423", "DIRECT", "cert1", "ads_txt", NOW),
        ("c.example", "pubmatic.com", "156423", "RESELLER", "", "ads_txt", NOW),
        ("d.example", "google.com", "pub-999", "DIRECT", "", "ads_txt", NOW),
    ]
    ix.conn.executemany(
        "INSERT OR REPLACE INTO ads_record VALUES (?,?,?,?,?,?,?)", rows)
    ix.conn.executemany("INSERT OR REPLACE INTO ads_var VALUES (?,?,?,?)", [
        ("a.example", "OWNERDOMAIN", "holdco.example", NOW),
        ("b.example", "OWNERDOMAIN", "holdco.example", NOW),
    ])
    ix.conn.executemany("INSERT OR REPLACE INTO seller VALUES (?,?,?,?,?,?,?)", [
        ("pubmatic.com", "156423", "Example Media Holdings Ltd",
         "holdco.example", "PUBLISHER", 0, NOW),
        ("google.com", "pub-999", None, None, "PUBLISHER", 1, NOW),
    ])
    ix.conn.commit()
    return ix


def test_reverse_seller_lookup_finds_portfolio(idx):
    """The pivot no free API exposes: seller ID -> every site declaring it."""
    assert idx.sites_for_seller("pubmatic.com", "156423") == [
        "a.example", "b.example", "c.example"
    ]


def test_ownerdomain_gives_self_published_portfolio(idx):
    assert idx.sites_for_owner("holdco.example") == ["a.example", "b.example"]


def test_holders_reflects_real_spread_not_case_view(idx):
    """A seller ID on three sites must not score as unique."""
    shared = Identifier(IdKind.SELLER_ID, "pubmatic.com/156423")
    lone = Identifier(IdKind.SELLER_ID, "google.com/pub-999")
    assert idx.holders(shared) == 3
    assert idx.holders(lone) == 1


def test_unknown_identifier_returns_zero_so_composite_falls_back(idx):
    assert idx.holders(Identifier(IdKind.SELLER_ID, "nope.com/1")) == 0
    assert idx.holders(Identifier(IdKind.EMAIL, "x@y.example")) == 0


def test_confidential_seller_keeps_type_but_not_name(idx):
    row = idx.conn.execute(
        "SELECT name, seller_type, is_confidential FROM seller WHERE seller_id='pub-999'"
    ).fetchone()
    assert row[0] is None and row[1] == "PUBLISHER" and row[2] == 1


def test_selectivity_index_protocol_satisfied(idx):
    from attribution_graph import SelectivityIndex
    assert isinstance(idx, SelectivityIndex)


# ---- account classification support -------------------------------------- #

def test_account_holders_counts_declaring_domains(idx):
    """The number that separates a real account from a pasted template line."""
    assert idx.account_holders("pubmatic.com", "156423") == 3
    assert idx.account_holders("google.com", "pub-999") == 1
    assert idx.account_holders("nobody.com", "1") == 0


def test_account_holders_can_split_by_relationship(idx):
    assert idx.account_holders("pubmatic.com", "156423", "DIRECT") == 2
    assert idx.account_holders("pubmatic.com", "156423", "RESELLER") == 1


def test_cid_lookup_finds_certified_records(idx):
    """A certification authority ID ties a record to a certified entity rather
    than to a string someone copied."""
    assert sorted(idx.domains_for_cid("cert1")) == ["a.example", "b.example"]
    assert idx.domains_for_cid("") == []


def test_boilerplate_accounts_surface_widely_duplicated_lines(idx):
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    idx.conn.executemany(
        "INSERT OR REPLACE INTO ads_record VALUES (?,?,?,?,?,?,?)",
        [(f"d{i}.example", "network.com", "999", "DIRECT", "", "ads_txt", now)
         for i in range(200)])
    idx.conn.commit()
    boiler = idx.boilerplate_accounts(threshold=150)
    assert ("network.com", "999", 200) in boiler
    assert not [b for b in boiler if b[1] == "156423"]


def test_shared_fingerprints_identify_pasted_files(idx):
    idx.record_fingerprint("a.example", "abc123", 300)
    idx.record_fingerprint("b.example", "abc123", 300)
    idx.record_fingerprint("c.example", "different", 5)
    assert sorted(idx.domains_sharing_fingerprint("abc123")) == [
        "a.example", "b.example"]
    assert idx.domains_sharing_fingerprint("different") == ["c.example"]


def test_app_ads_records_are_kept_separate(idx):
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    idx.conn.execute(
        "INSERT OR REPLACE INTO ads_record VALUES (?,?,?,?,?,?,?)",
        ("a.example", "pubmatic.com", "156423", "DIRECT", "", "app_ads_txt", now))
    idx.conn.commit()
    # Same account across web and app inventory: one holder domain, two records.
    assert idx.account_holders("pubmatic.com", "156423") == 3
