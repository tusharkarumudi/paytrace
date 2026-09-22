"""Planted-identifier detection."""

import asyncio as _asyncio

from attribution_graph import Claim, Identifier, IdKind, Predicate, Reliability

from paytrace.adversarial import (
    Assessment,
    Verdict,
    apply_assessments,
    check_asymmetry,
)
from paytrace.adversarial import check_load_bearing as _lb


def test_asymmetry_flags_the_smaller_property():
    """A tiny site carrying a major property's ID is template reuse or planting,
    not evidence of common control."""
    ok, why = check_asymmetry(
        "scraper.example",
        ["scraper.example", "bigmedia.example"],
        {"scraper.example": 2, "bigmedia.example": 900},
    )
    assert ok is False
    assert "more established" in why


def test_asymmetry_silent_when_properties_are_comparable():
    ok, _ = check_asymmetry("a.example", ["a.example", "b.example"],
                            {"a.example": 40, "b.example": 55})
    assert ok is None


def test_suspect_and_inert_verdicts_demote():
    for v in (Verdict.SUSPECT, Verdict.INERT):
        assert Assessment("x", v).should_demote
    for v in (Verdict.CORROBORATED, Verdict.UNVERIFIED):
        assert not Assessment("x", v).should_demote


def _claim(val):
    return Claim(
        subject=Identifier(IdKind.DOMAIN, "a.example"),
        predicate=Predicate.SHARES_ANALYTICS_ID,
        object=Identifier(IdKind.ANALYTICS_ID, val),
        collector="analytics_ids", source_url="https://a.example",
        reliability=Reliability.AUTHORITATIVE,
    )


def test_failed_checks_demote_but_never_delete():
    """A planted identifier is still evidence -- of an attempt to frame someone.
    Deleting it hides the most interesting fact in the case."""
    c = _claim("adsense:1234567890123456")
    out = apply_assessments([c], {
        "adsense:1234567890123456": Assessment(
            "adsense:1234567890123456", Verdict.INERT,
            checks={"load_bearing": "loader absent"}),
    })
    assert len(out) == 1
    assert out[0].weight == 0.0
    assert "planted-identifier check" in out[0].raw["demoted"]
    assert out[0].raw["adversarial_checks"]["load_bearing"] == "loader absent"


def test_corroborated_identifiers_keep_full_weight():
    c = _claim("adsense:1234567890123456")
    out = apply_assessments([c], {
        "adsense:1234567890123456": Assessment(
            "adsense:1234567890123456", Verdict.CORROBORATED,
            checks={"reciprocity": "sellers.json names the domain"}),
    })
    assert out[0].weight == 1.0
    assert "adversarial_checks" in out[0].raw


def test_unassessed_claims_pass_through_unchanged():
    c = _claim("ga4:G-ABCDEF1234")
    out = apply_assessments([c], {})
    assert out[0].weight == 1.0


# ---- load-bearing checks are specific to the identifier -------------------- #


_G, _P = "G-REAL000001", "G-PLANT00001"


def _loader(i):
    return f'<script async src="https://www.googletagmanager.com/gtag/js?id={i}"></script>'


def _check(value, html, scheme="ga4"):
    return _asyncio.run(_lb(None, "x.example", scheme, value, html=html))[0]


def test_a_commented_plant_does_not_frame_the_genuine_id():
    """One planted ID inside a comment used to make EVERY identifier on the
    page read as planted: the check matched any ID in any comment. The attack
    framed the real operator instead of being caught."""
    assert _check(_G, _loader(_G) + f"<!-- {_P} -->") is True


def test_a_real_loader_does_not_launder_a_planted_id():
    """The loader check matched any gtag loader, so a planted ID written as
    plain text was reported live because a genuine loader sat beside it."""
    assert _check(_P, _loader(_G) + f"<p hidden>{_P}</p>") is False


def test_an_id_only_in_a_comment_is_not_load_bearing():
    assert _check(_P, _loader(_G) + f"<!-- {_P} -->") is False


def test_a_loaded_id_also_mentioned_in_a_comment_stays_live():
    """A working loader for this ID is decisive."""
    assert _check(_G, _loader(_G) + f"<!-- was {_G} -->") is True


def test_a_prefix_of_another_id_is_not_that_id():
    """G-REAL000001 is a substring of G-REAL0000012."""
    assert _check(_G, _loader("G-REAL0000012")) is None


def test_an_absent_id_is_inconclusive_not_planted():
    assert _check(_P, _loader(_G)) is None


def test_adsense_matches_on_the_publisher_digits():
    html = ('<script src="https://pagead2.googlesyndication.com/pagead/js/'
            'adsbygoogle.js?client=ca-pub-1234567890123456"></script>')
    assert _check("1234567890123456", html, scheme="adsense") is True
    assert _check("6543210987654321", html, scheme="adsense") is None


def test_mixed_case_identifiers_are_demoted():
    """Identifier stores `ga4:g-rival00001`; the assessment reports the ID as
    found, `ga4:G-RIVAL00001`. A case-sensitive lookup never matched, so a
    planted GA4 or GTM ID kept full weight. Only all-digit AdSense IDs worked,
    which is the only case the earlier test exercised."""
    for key in ("ga4:G-RIVAL00001", "gtm:GTM-ABC123"):
        c = _claim(key)
        out = apply_assessments([c], {key: Assessment(key, Verdict.INERT,
                                                      checks={"load_bearing": "comment"})})
        assert out[0].weight == 0.0, key
        assert "planted-identifier check" in out[0].raw["demoted"]
