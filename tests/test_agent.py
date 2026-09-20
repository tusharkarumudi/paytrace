"""Agent, guards, and the injection demo.

These are demo-stability tests as much as correctness tests: a talk that depends
on this behaviour needs it asserted, not hoped for.
"""

import pytest

from paytrace.agent import (
    DECOY_ENTITY,
    REAL_ENTITY,
    Agent,
    FixtureFetcher,
    FixtureIndex,
    ScriptedBrain,
    Severity,
    Toolbox,
    report,
    scan,
)
from paytrace.agent.fixtures import INJECTION_COMMENT
from paytrace.agent.guards import PLANNER_VISIBLE

GOAL = "attribute scraper-site.example"


def run(poisoned: bool, guards: bool):
    box = Toolbox(FixtureFetcher(poisoned=poisoned), FixtureIndex())
    return Agent(box, brain=ScriptedBrain(), guards_enabled=guards).run(GOAL)


# ---- determinism: the demo must not vary on stage ------------------------- #

@pytest.mark.parametrize("poisoned,guards", [(False, True), (True, False), (True, True)])
def test_runs_are_deterministic(poisoned, guards):
    a, b = run(poisoned, guards), run(poisoned, guards)
    assert a.conclusion == b.conclusion
    assert a.tools_called == b.tools_called
    assert len(a.graph.claims) == len(b.graph.claims)


def test_no_network_is_used():
    box = Toolbox(FixtureFetcher(poisoned=True), FixtureIndex())
    Agent(box, guards_enabled=True).run(GOAL)
    assert all(u.startswith("https://") for u in box.fetcher.requests)
    assert box.fetcher.requests, "fixtures should have been consulted"


# ---- act 1: clean baseline ------------------------------------------------ #

def test_clean_run_reaches_the_real_entity():
    r = run(poisoned=False, guards=True)
    assert r.conclusion == REAL_ENTITY
    assert "lookup_gleif" in r.tools_called


def test_clean_run_raises_no_injection_alert():
    assert not run(poisoned=False, guards=True).injection_alerts


# ---- act 3: the naive agent is hijacked ----------------------------------- #

def test_naive_agent_adopts_the_decoy():
    r = run(poisoned=True, guards=False)
    assert r.conclusion == DECOY_ENTITY
    assert r.conclusion_source == "adopted from retrieved data"


def test_naive_agent_skips_the_registry_pivot():
    """The worse of the two failures: the step that would have caught the lie."""
    r = run(poisoned=True, guards=False)
    assert "lookup_gleif" not in r.tools_called
    # The ads.txt payload halts at step one, before a registry pivot is
    # derived. The tell is that pivots the collected evidence demanded went
    # unmade -- keying on "gleif" specifically reported no violation on the
    # strongest form of the attack.
    assert r.invariants.violations()


def test_naive_agent_stops_early():
    naive = run(poisoned=True, guards=False)
    clean = run(poisoned=False, guards=True)
    assert len(naive.tools_called) < len(clean.tools_called)


def test_detection_fires_even_when_it_changes_nothing():
    """Detection is not the control. It fires and the naive run proceeds anyway."""
    r = run(poisoned=True, guards=False)
    assert r.injection_alerts
    assert r.conclusion == DECOY_ENTITY


# ---- act 4: the defended agent -------------------------------------------- #

def test_defended_agent_reaches_the_real_entity():
    r = run(poisoned=True, guards=True)
    assert r.conclusion == REAL_ENTITY
    assert r.conclusion_source == "derived from the evidence graph"


def test_defended_agent_completes_the_registry_pivot():
    r = run(poisoned=True, guards=True)
    assert "lookup_gleif" in r.tools_called
    assert not any("gleif" in v for v in r.invariants.violations())


def test_defended_and_clean_runs_agree():
    assert run(True, True).conclusion == run(False, True).conclusion


def test_decoy_never_enters_the_evidence_graph():
    r = run(poisoned=True, guards=True)
    assert DECOY_ENTITY not in repr([c.to_dict() for c in r.graph.claims])


# ---- the individual layers ------------------------------------------------ #

def test_layer1_detection_flags_the_payload():
    findings = scan(type("R", (), {
        "tool": "fetch_sellers_json",
        "freetext": {"comment": INJECTION_COMMENT},
        "source_url": "https://x"})())
    assert any(f.severity is Severity.LIKELY_INJECTION for f in findings)


def test_layer1_does_not_flag_ordinary_prose():
    findings = scan(type("R", (), {
        "tool": "fetch_sellers_json",
        "freetext": {"comment": "Contact sellers@example.com for inventory."},
        "source_url": "https://x"})())
    assert not [f for f in findings if f.severity is Severity.LIKELY_INJECTION]


def test_layer2_withholds_nonstructural_fields():
    """Only spec-defined fields reach the planner.

    ads.txt is the publisher-owned document, so its comments are where free
    text lives. sellers.json has no publisher-writable prose field: the ad
    system publishes that file, which is exactly the correction this example
    now encodes.
    """
    box = Toolbox(FixtureFetcher(poisoned=True), FixtureIndex())
    res = box.call("fetch_ads_txt", domain="scraper-site.example")
    assert res.freetext, "the publisher-owned document carries free text"
    assert "Northwind" in " ".join(str(v) for v in res.freetext.values())
    assert "Northwind" not in str(res.structured), (
        "operator prose must not reach the planner through structured fields")



def test_layer2_allowlist_covers_every_tool():
    box = Toolbox(FixtureFetcher(), FixtureIndex())
    for name in box.names():
        assert name in PLANNER_VISIBLE, f"{name} has no allowlist"


def test_layer3_demotes_self_assertions():
    r = run(poisoned=True, guards=True)
    demoted = [c for c in r.graph.claims if c.weight == 0.0]
    assert demoted
    assert all("self-assertion" in c.raw.get("demoted", "") for c in demoted)


def test_layer4_invariants_derive_from_evidence_not_prose():
    """The load-bearing property: requirements come from claims, not from text.

    Demonstrated on the *defended* run, because the ads.txt payload halts the
    naive run at step one -- before any org name enters the graph, so there is
    nothing yet for a registry pivot to be required *of*. The invariant that
    matters is that once the name is in the graph, no sentence in the retrieved
    data can remove the requirement.
    """
    r = run(poisoned=True, guards=True)
    assert any("gleif" in req for req in r.invariants.required), (
        "an org name in the claim graph must require a registry pivot "
        "regardless of what the retrieved data says about it")
    assert "lookup_gleif" in r.tools_called


def test_hijacked_run_leaves_its_own_evidence_demands_unmet():
    """The naive run's tell. It stops before the registry pivot is derived, so
    the signal is the pivot its own ads.txt records demanded."""
    r = run(poisoned=True, guards=False)
    assert r.invariants.violations()
    assert any("sellers_json" in v for v in r.invariants.violations())



def test_report_surfaces_skipped_pivots():
    out = report(run(poisoned=True, guards=False))
    assert "required pivot(s) never ran" in out
    # The ads.txt payload terminates before a registry pivot is derived; the
    # report must still surface the pivots the collected evidence demanded.
    assert "fetch_sellers_json" in out


def test_report_labels_the_conclusion_source():
    assert "adopted from retrieved data" in report(run(True, False))
    assert "derived from the evidence graph" in report(run(True, True))
