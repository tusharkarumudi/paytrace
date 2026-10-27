"""Differential retrieval: is the declaration the same for everyone?

The gap this closes: every check in the toolkit reasons about the ads.txt we
were shown, and nothing compared it against anyone else's copy. A site serving
one file to this tool and another to a browser defeated all of them at once,
and the report read as though the declaration were the site's rather than ours.
"""

import asyncio

from paytrace.adstxt import parse
from paytrace.cloaking import (
    BROWSER_UA,
    CONSISTENT,
    COSMETIC,
    MATERIAL,
    UNVERIFIED,
    Variant,
    account_set,
    check_cloaking,
    compare,
)

HONEST = ("# the real file\n"
          "google.com, pub-0000000000000314, DIRECT, f08c47fec0942fa0\n"
          "adrelay.example, 7kQmZ2bXr4TnWp8Ls, DIRECT\n"
          "OWNERDOMAIN=site.example\n")


def _variant(label, body, sha="x"):
    doc = parse(body, "site.example")
    return Variant(label, account_set(body, "site.example"), doc.owner_domain,
                   doc.record_count, sha)


def test_identical_copies_are_consistent():
    assert compare([_variant("a", HONEST), _variant("b", HONEST)]).verdict \
        == CONSISTENT


def test_comments_order_and_whitespace_are_not_cloaking():
    """Two honest copies of the same file differ constantly. A byte comparison
    would report cloaking on every site in the world."""
    shuffled = ("adrelay.example,7kQmZ2bXr4TnWp8Ls,DIRECT\r\n"
                "# a different comment\n"
                "google.com, pub-0000000000000314, DIRECT\n"
                "OWNERDOMAIN=site.example\n")
    r = compare([_variant("a", HONEST, "1"), _variant("b", shuffled, "2")])
    assert r.verdict == COSMETIC, r.differences
    assert not r.cloaked


def test_a_different_account_set_is_material():
    hidden = ("google.com, pub-0000000000000314, DIRECT\n"
              "hidden-ssp.example, 4242, DIRECT\n"
              "OWNERDOMAIN=site.example\n")
    r = compare([_variant("this tool", HONEST), _variant("a browser", hidden)])
    assert r.verdict == MATERIAL
    assert r.cloaked
    assert any("hidden-ssp.example/4242" in d for d in r.differences)
    assert any("NOT to this tool" in d for d in r.differences)


def test_a_changed_relationship_is_material():
    """DIRECT becoming RESELLER changes who is said to be paid."""
    flipped = HONEST.replace("7kQmZ2bXr4TnWp8Ls, DIRECT",
                             "7kQmZ2bXr4TnWp8Ls, RESELLER")
    r = compare([_variant("a", HONEST), _variant("b", flipped)])
    assert r.verdict == MATERIAL
    assert any("RESELLER" in d for d in r.differences)


def test_a_changed_ownerdomain_is_reported():
    elsewhere = HONEST.replace("OWNERDOMAIN=site.example",
                               "OWNERDOMAIN=elsewhere.example")
    r = compare([_variant("a", HONEST), _variant("b", elsewhere)])
    assert r.verdict == MATERIAL
    assert any("OWNERDOMAIN differs" in d for d in r.differences)


def test_one_copy_proves_nothing():
    """The honest verdict when the second retrieval failed: a single copy
    cannot show whether it is the copy everyone gets."""
    r = compare([_variant("a", HONEST),
                 Variant("b", frozenset(), "", 0, ok=False, note="timeout")])
    assert r.verdict == UNVERIFIED
    assert "cannot show whether it is the copy everyone gets" in r.reasons[0]


# ---- the async path -------------------------------------------------------- #

class _R:
    def __init__(self, text):
        self.status, self.text = 200, text


class _Cloaker:
    """Serves a second, larger declaration to anything that looks like a
    browser. This is the attack the check exists for."""

    EXTRA = "hidden-ssp.example, 4242, DIRECT\n"

    def __init__(self):
        self.calls = []

    async def get(self, url, headers=None, egress="", **kw):
        ua = (headers or {}).get("User-Agent", "")
        self.calls.append((url, ua, egress))
        return _R(HONEST + self.EXTRA if "Mozilla" in ua else HONEST)


def test_ua_cloaking_is_detected_end_to_end():
    f = _Cloaker()
    r = asyncio.run(check_cloaking(f, "site.example", browser_ua=BROWSER_UA))
    assert r.cloaked, r.summary()
    assert r.misrepresented, "the UA variant must be flagged as such"
    assert any("hidden-ssp.example/4242" in d for d in r.differences)
    assert len(f.calls) == 2
    assert f.calls[0][1] == "" and "Mozilla" in f.calls[1][1]


def test_without_the_flag_no_second_request_is_made():
    """It misrepresents the client, so it does not happen unless asked for."""
    f = _Cloaker()
    r = asyncio.run(check_cloaking(f, "site.example"))
    assert len(f.calls) == 1
    assert not r.misrepresented
    assert r.verdict == UNVERIFIED


def test_an_egress_variant_misrepresents_nothing():
    """Same request, different exit: catches selective serving by IP, and the
    request is identical to the first in every respect we control."""
    f = _Cloaker()
    r = asyncio.run(check_cloaking(f, "site.example",
                                   egress_labels=("second",)))
    assert len(f.calls) == 2
    assert f.calls[1][2] == "second"
    assert all(c[1] == "" for c in f.calls), "no UA was altered"
    assert not r.misrepresented
    assert r.verdict == CONSISTENT


def test_a_failing_retrieval_does_not_crash_the_check():
    class Broken(_Cloaker):
        async def get(self, url, headers=None, egress="", **kw):
            if (headers or {}).get("User-Agent"):
                raise RuntimeError("connection reset")
            return _R(HONEST)

    r = asyncio.run(check_cloaking(Broken(), "site.example",
                                   browser_ua=BROWSER_UA))
    assert r.verdict == UNVERIFIED
    assert any(not v.ok for v in r.variants)


def test_every_retrieval_goes_through_the_fetcher():
    """A check whose own requests skipped the policy and SSRF guards, or never
    reached the evidence package, would not be evidence of anything."""
    import inspect

    from paytrace import cloaking

    src = inspect.getsource(cloaking.check_cloaking)
    assert "fetcher.get(" in src
    assert "httpx" not in src, "the check must not open its own transport"
