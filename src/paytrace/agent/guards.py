"""Defenses against instructions embedded in collected data.

The threat is specific to this domain and worth stating precisely.

In most agent deployments, untrusted content in tool output is an edge case: a
web page the agent happened to read, an email in an inbox. In attribution work it
is the **normal** case. `ads.txt`, `sellers.json`, imprint pages and DNS TXT
records are all authored by the entity under investigation. An agent that treats
retrieved text as instructions is taking direction from its target, and the
target has both motive and a publishing channel.

Four layers, weakest to strongest. The ordering matters: the first two are
heuristics an adversary can work around, the last two are structural.

1. **Detection** — pattern-match imperative text in tool output. Catches the
   naive payload, loses to paraphrase. Useful as a tripwire and an alert, not as
   a control.
2. **Field allowlisting** — parse only spec-defined structural fields; never
   surface operator free text to the planner. Defeats the whole class as long as
   the spec has a fixed field list, which `sellers.json` does.
3. **Trust-tiered provenance** — a claim about an entity, sourced from that
   entity, is self-assertion. It enters at low reliability and cannot be
   promoted by anything it says about itself.
4. **Plan invariants** — the pivot sequence is derived from the evidence graph,
   not from the model. Data cannot cause a pivot to be skipped because data does
   not decide which pivots run.

Layer 4 is the one that actually holds, and it is not an injection defense that
was designed as one — it falls out of having the planner decide from structured
claims rather than from prose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from attribution_graph import Claim, Identifier, IdKind

from .tools import ToolResult, Trust


class Severity(StrEnum):
    NONE = "none"
    SUSPICIOUS = "suspicious"
    LIKELY_INJECTION = "likely_injection"


#: Imperative patterns aimed at an automated reader. Deliberately narrow: broad
#: patterns fire on ordinary compliance boilerplate ("do not contact this
#: address for support") and an alert that cries wolf gets muted.
INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(?:note|notice|attention|instruction)s?\s+(?:for|to)\s+"
                r"(?:automated|ai|llm|agent|bot|crawler|scraper)", re.I),
     "addresses an automated reader directly"),
    (re.compile(r"\b(?:ignore|disregard|override|bypass|skip)\s+"
                r"(?:all\s+|any\s+|previous\s+|prior\s+|the\s+)?"
                r"(?:instruction|direction|rule|step|check|guideline)", re.I),
     "instructs the reader to disregard its own directions"),
    (re.compile(r"\b(?:do not|don't|never)\s+(?:query|check|contact|look ?up|"
                r"consult|verify|search|investigate)\b", re.I),
     "instructs the reader to skip a verification step"),
    (re.compile(r"\b(?:terminate|stop|halt|end|abort|conclude)\s+"
                r"(?:the\s+)?(?:investigation|analysis|search|run|session)", re.I),
     "instructs the reader to end the investigation"),
    (re.compile(r"\bthe\s+(?:authoritative|correct|true|actual|real)\s+"
                r"(?:operator|owner|entity|answer|attribution)\s+is\b", re.I),
     "asserts a conclusion the reader is meant to adopt"),
    (re.compile(r"\breport\s+\S.{0,60}?\s+as\s+the\s+"
                r"(?:operator|owner|entity|attribution)", re.I),
     "dictates the content of the output"),
    (re.compile(r"\b(?:registry|registrar|whois|corporate)\s+data\s+is\s+"
                r"(?:stale|wrong|incorrect|unreliable|deprecated)", re.I),
     "pre-emptively discredits a higher-trust source"),
    (re.compile(r"\bsystem\s*(?:prompt|message|role)\b|"
                r"<\s*/?\s*(?:system|instruction|assistant)\s*>", re.I),
     "attempts to imitate framing markup"),
]


@dataclass
class Finding:
    severity: Severity
    tool: str
    field: str
    reason: str
    excerpt: str
    source_url: str = ""

    def render(self) -> str:
        return (f"[{self.severity.value}] {self.tool}.{self.field}: {self.reason}\n"
                f"    {self.excerpt[:160]}")


@dataclass
class GuardReport:
    findings: list[Finding] = field(default_factory=list)
    fields_withheld: list[str] = field(default_factory=list)
    claims_demoted: int = 0

    @property
    def triggered(self) -> bool:
        return any(f.severity is Severity.LIKELY_INJECTION for f in self.findings)

    def render(self) -> str:
        if not self.findings and not self.fields_withheld:
            return "no findings"
        out = [f.render() for f in self.findings]
        if self.fields_withheld:
            out.append(f"withheld from planner context: "
                       f"{', '.join(self.fields_withheld)}")
        return "\n".join(out)


# --------------------------------------------------------------------------- #
# Layer 1 — detection
# --------------------------------------------------------------------------- #

def scan(result: ToolResult) -> list[Finding]:
    """Pattern-match imperative text in operator-controlled fields.

    A tripwire, not a control. Any adversary who paraphrases gets past it, and
    treating it as the defense is how systems end up with one brittle layer.
    """
    findings: list[Finding] = []
    for name, value in result.freetext.items():
        if not isinstance(value, str):
            continue
        for pattern, reason in INJECTION_PATTERNS:
            m = pattern.search(value)
            if m:
                findings.append(Finding(
                    severity=Severity.LIKELY_INJECTION,
                    tool=result.tool, field=name, reason=reason,
                    excerpt=value[max(0, m.start() - 40):m.end() + 120],
                    source_url=result.source_url))
                break
        else:
            # Long prose in a field with no defined semantics is odd even
            # without a matching pattern.
            if len(value) > 400:
                findings.append(Finding(
                    severity=Severity.SUSPICIOUS,
                    tool=result.tool, field=name,
                    reason=f"{len(value)} characters of prose in a non-semantic field",
                    excerpt=value[:200], source_url=result.source_url))
    return findings


# --------------------------------------------------------------------------- #
# Layer 2 — field allowlisting
# --------------------------------------------------------------------------- #

#: Fields the planner may see, by tool. Anything else is operator prose.
PLANNER_VISIBLE: dict[str, set[str]] = {
    "fetch_ads_txt": {"domain", "sellers", "variables"},
    "fetch_sellers_json": {"seller_id", "name", "domain", "seller_type",
                           "is_confidential", "found"},
    "extract_analytics_ids": {"domain", "identifiers"},
    "reverse_lookup_identifier": {"identifier", "holders", "domains"},
    "lookup_gleif": {"records"},
    "lookup_companies_house": {"company_number", "officers"},
    "lookup_rdap": {"entities"},
}


def restrict(result: ToolResult) -> tuple[ToolResult, list[str]]:
    """Strip anything outside the allowlist before the planner sees it."""
    allowed = PLANNER_VISIBLE.get(result.tool)
    if allowed is None:
        return result, []
    withheld = [k for k in result.structured if k not in allowed]
    for k in withheld:
        result.structured.pop(k, None)
    withheld += [f"freetext.{k}" for k in result.freetext]
    return result, withheld


# --------------------------------------------------------------------------- #
# Layer 3 — trust-tiered provenance
# --------------------------------------------------------------------------- #

def demote_self_assertions(result: ToolResult, subject_domains: set[str]) -> int:
    """Zero the weight of claims where source and subject are the same party.

    A publisher's own `sellers.json` naming its own operator is a self-assertion.
    It is worth recording and worth nothing on its own, and the scoring model
    already refuses to attribute on a single self-published group — this makes
    that explicit rather than incidental.
    """
    if result.trust is not Trust.SUBJECT:
        return 0
    host = result.source_url.split("//")[-1].split("/")[0].lower()
    if not any(host.endswith(d) for d in subject_domains):
        return 0
    n = 0
    for c in result.claims:
        c.weight = 0.0
        c.raw["demoted"] = ("self-assertion: the source is the subject of the "
                            "claim, so it corroborates nothing")
        n += 1
    return n


# --------------------------------------------------------------------------- #
# Layer 4 — plan invariants
# --------------------------------------------------------------------------- #

@dataclass
class PlanInvariants:
    """Pivots the run must perform, derived from evidence rather than prose.

    This is the layer that holds. The planner does not choose whether to query a
    registry — the presence of an org name in the claim graph requires it. There
    is no sentence an adversary can write into a data field that removes a
    required pivot, because prose is not an input to this decision.
    """

    required: set[str] = field(default_factory=set)
    completed: set[str] = field(default_factory=set)
    skipped: list[tuple[str, str]] = field(default_factory=list)

    def require_from_claims(self, claims: list[Claim]) -> None:
        for c in claims:
            obj = c.object if isinstance(c.object, Identifier) else None
            if obj is None:
                continue
            if obj.kind is IdKind.SELLER_ID:
                self.required.add(f"fetch_sellers_json:{obj.value}")
            elif obj.kind is IdKind.ORG_NAME:
                self.required.add(f"lookup_gleif:{obj.value}")
            elif obj.kind is IdKind.COMPANY_NUMBER:
                self.required.add(f"lookup_companies_house:{obj.value}")
            elif obj.kind is IdKind.ANALYTICS_ID:
                self.required.add(f"reverse_lookup_identifier:{obj.value}")

    def complete(self, key: str) -> None:
        self.completed.add(key)

    def skip(self, key: str, reason: str) -> None:
        self.skipped.append((key, reason))

    @property
    def outstanding(self) -> set[str]:
        return self.required - self.completed - {k for k, _ in self.skipped}

    def violations(self) -> list[str]:
        """Required pivots that were never run. Empty is the only passing state."""
        return sorted(self.outstanding)


# --------------------------------------------------------------------------- #

def apply_all(
    result: ToolResult,
    subject_domains: set[str],
    *,
    enabled: bool = True,
) -> tuple[ToolResult, GuardReport]:
    """Run every layer. With ``enabled=False`` only detection runs, so the
    naive path can be demonstrated with the alerts visible but not acted on."""
    report = GuardReport(findings=scan(result))
    if not enabled:
        return result, report
    result, withheld = restrict(result)
    report.fields_withheld = withheld
    report.claims_demoted = demote_self_assertions(result, subject_domains)
    return result, report
