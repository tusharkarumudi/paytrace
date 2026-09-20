"""Planted-identifier detection."""

from attribution_graph import Claim, Identifier, IdKind, Predicate, Reliability

from paytrace.adversarial import (
    Assessment,
    Verdict,
    apply_assessments,
    check_asymmetry,
)


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
