# Response to external audit

Twenty-five findings. I agree with twenty-three, partially disagree with one,
and disagree with one. This records what changed, what did not, and why.

**The audit's central point is correct and I have acted on it:** the system is
an evidence-ranking engine and the API described it as a probabilistic
attribution engine. My own methodology audit said "an ordering, not a measured
frequency" and then shipped a field called `probability` and a band called
`ATTRIBUTED`. That gap between documentation and surface is exactly the failure
the auditor identified.

---

## Fixed — the four that were dangerous

**1. CI failed open.** `|| true` on integration tests, examples and `pip-audit`.
Documentation claimed the integration suite gated releases; GitHub did not.
All three now fail the build. `pip-audit` is renamed "Dependency CVEs (fails the
build)" because a scan that cannot fail is theatre.

**2. `max_bytes` did not prevent OOM.** `r.content[:max_bytes]` materialises the
whole body first, so a 5 GB response exhausted memory before the slice applied.
The docstring claimed a protection the code did not provide, which is the worst
class of bug. Now streams with `aiter_bytes()` and stops reading at the cap,
after transfer decoding so decompression bombs are bounded by the same limit.

**3. Egress did not control transport.** `EgressPool` sat beside a single
`httpx.AsyncClient` that never used it; `self._clients` was dead. The manifest
would have recorded a vantage point the request never used — fabricated
provenance, worse than none. `Fetcher.client_for(label)` now builds one proxied
client per egress, and a misconfigured egress raises rather than silently
falling back to direct.

**4. Cache key omitted the egress.** A US capture would have served a request
that asked for a DE vantage point. Key now includes egress label and country.

## Fixed — semantics

**5. Stopped calling the output a probability.** `log(1/selectivity)` informs
the *denominator* of a likelihood ratio; `P(evidence | same entity)` is not
modelled and varies enormously between a shared GA4 ID and a shared company
address. Multiplying by a subjective reliability coefficient does not restore
the missing term. Output now carries `calibration_status: "unvalidated"` and a
`probability_note` stating plainly what the number is.

**23. Renamed the bands.** `ATTRIBUTED` / `PROBABLE` / `POSSIBLE` became
`STRONG_EVIDENCE` / `MODERATE_EVIDENCE` / `LIMITED_EVIDENCE`, and ICD 203
estimative language ("almost certainly") became evidence-strength phrasing
("strongly supported by the evidence"). The auditor's argument is the right one:
downstream users quote the strongest surface, and a disclaimer in a methodology
file does not travel with a word pasted into a report.

**7 & 21. Dependence is typed metadata, and the default is conservative.**
`Claim.dependence_class` is declared by the collector and always wins; regex
matching survives only as a fallback for older claims. Unrecognised evidence is
now `UNKNOWN` and discounted at 0.20, not assumed independent. My original
argument — that a wrong discount is harder to notice than a missing one — was
worse than the auditor's: for a model whose dominant failure mode is
overconfidence, unrecognised evidence should fail conservative.

**9. Agent no longer reimplements domain logic.** The `sellers.json` tool
hard-coded `ORG_NAME` while `classify_seller_name()` existed, so the agent path
typed individual publishers as organisations and routed them to corporate
registries that hold no record. It now delegates.

**12. Version reads source truth.** `importlib.metadata.version()` returned a
fallback for an uninstalled source tree, so a valid run reported a divergence
that did not exist.

**11. Test taxonomy.** Markers for `network`, `browser`, `integration`,
`adversarial`, `slow`. Default `addopts` excludes network and browser, so
`pytest` is green on a machine without DNS or Chromium — which is an environment
fact, not a defect.

**25. Exception taxonomy.** `EXPECTED_FAILURES` covers the world being
uncooperative; anything else is our defect and raises under `strict=True`. A
`TypeError` reporting as "tool failed" made production bugs indistinguishable
from a source being down.

---

## Where I partially disagree — the monorepo

The auditor is right about the operational cost: four CI files, four LICENSEs,
four CHANGELOGs, synchronised versioning, and integration tests that hope
siblings exist at `../`. That is a distributed monorepo, and it is fragile.

But I do not think the answer is one repository *and* one package. The
`attribution-graph` boundary is real and load-bearing: **it performs no network
I/O**, which is precisely what makes its scoring auditable, and that guarantee
is enforced by the package boundary rather than by convention. Someone who wants
the inference model should not have to install an HTTP client and 36 collectors.

So: **one repository, four published packages.** A workspace, not a merge. That
takes the auditor's operational fix — one CI pipeline where integration failures
are fatal, one release process, no duplicated workflow config — while keeping
the boundary that carries a technical guarantee.

This is staged rather than done. The repository layout change is mechanical but
touches every path in `PUSH_INSTRUCTIONS.md`, and doing it half-way would be
worse than either end state.

---

## Where I disagree

**14, on cache versus evidence.** The auditor reads these as conflated. They are
already separate objects: `EvidenceLog` writes content-addressed, hash-chained
captures under `evidence/`, while `.eae-cache/` is a replaceable performance
cache. The `net.py` comment saying "the cached body is the artifact" is wrong and
has been corrected — but the architecture was right; only the comment was not.

The auditor's underlying point about **capture completeness** is correct and is
now staged: the evidence record should carry the redirect chain, request and
response headers, TLS peer info, wire-body versus decoded-body hashes, and
truncation state. That is a real gap.

---

## Staged, with reasons

**3. DNS rebinding / TOCTOU.** Correct, and not yet fixed. Validation resolves
the host; `httpx` resolves again when connecting. Closing it properly means a
custom transport that pins the validated address while preserving Host header,
SNI and certificate verification — worth doing carefully rather than quickly.
**Documented as a known limitation in `SECURITY.md` and the audit** rather than
left implied.

**6. Candidate-generation context.** The auditor is right that a global prior
applied to deliberately-selected candidates is selection bias, and that no amount
of tuning fixes it. The fix is an `AssessmentContext` recording how a candidate
entered the system, so calibration can be conditional on the selection rule.
That is a modelling change that should land *with* the calibration study, not
before it.

**8. `Reliability` conflates three concepts** — observation fidelity, source
independence, binding strength. This is the deepest finding after #5, and the
auditor is right that `AUTHORITATIVE` on a subject-controlled page is
misleading. Splitting it is a breaking change across every collector, and it
should be done once, deliberately.

**13. Capture completeness.** Above.

**24. Predicate policy table.** Behaviour currently spread across `model.py`,
`scoring.py`, `dependence.py` and collectors. Consolidating is correct and
mechanical.

---

## What the audit changed about the project's claim

From:

> determine which legal entity or person operates a domain, with a confidence
> figure

To:

> build an auditable evidence graph for entity-attribution investigations, rank
> candidate relationships by evidence strength, and preserve the provenance
> necessary for independent review

The auditor's closing observation is the one worth keeping: narrowing the claim
makes the project **more** credible, not less. The narrow claim is supported by
what exists. The broad one is not, and would not have survived first contact
with a reviewer who checked.
