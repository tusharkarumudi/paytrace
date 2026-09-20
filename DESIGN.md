# Attribution toolchain — design summary

**v1.7.0** · Apache-2.0 · Tushar Karumudi · 723 tests · **pre-release / experimental**

---

## What it does

Build an auditable evidence graph for entity-attribution investigations, rank
candidate relationships by **evidence strength**, and preserve the provenance
needed for independent review.

The claim used to be "determine which entity operates a domain, with a
confidence figure." An external audit made the case that the narrower claim is
the one the mathematics supports — and that narrowing it makes the project more
credible, not less. `log(1/selectivity)` informs the *denominator* of a
likelihood ratio; `P(evidence | same entity)` is not modelled. Output carries
`calibration_status: "unvalidated"` and bands named for evidence strength
(`STRONG_EVIDENCE`), not probability (`ATTRIBUTED`).

The core insight it exploits: **an operator can hide registrant, hosting, DNS
and email — but to be paid, a real legal entity must be named to an ad system,
and `sellers.json` publishes that name.**

```
site/ads.txt → google.com, pub-XXXX, DIRECT
             → sellers.json → "HOÀNG PHÚ LINH"
             → reverse lookup by name → every other account and site they hold
```

## Architecture

| Package | Role | Tests |
|---|---|---:|
| `attribution-graph` | Inference core. **No network I/O** — every number is a pure function of claims plus index counts, which is what makes scoring auditable. | 172 |
| `paytrace` | 36 collectors, corpus index, agent, fingerprinting, egress | 376 |
| `handle-correlation` | Same-actor scoring for observed handles | 59 |
| `attribution-suite` | One CLI, LLM orchestrator, integration suite | 94 |

## The model

```
llr = reliability × weight × decay(age) × log(1 / selectivity)
```

Five rules do the work:

1. **Selectivity is measured, not assigned.** A unique analytics ID scores ~14 nats, a shared CDN IP ~0 — without the model being told what a CDN is.
2. **Correlation groups** stop stacking within a source. 400 commits from one repo count once.
3. **Dependence classes** stop stacking *across* sources with a common cause. One operator configuring one property emits analytics, favicon and headers together — three groups, one decision.
4. **`GROUP_CAP < |log(PRIOR_ODDS)|`** makes corroboration arithmetic, not analyst discipline. No single inferential group crosses the merge threshold.
5. **Absence is typed.** "Not checked", "checked and absent" and "expected absent" are different claims. An undeclared source contributes zero.

## Three things it treats differently from most tooling

**Untrusted input is the default, not an edge case.** `ads.txt`, `sellers.json` and imprint pages are authored by the entity under investigation. Four guard layers follow; two hold structurally rather than heuristically. Demonstrated by a four-act injection demo where a spec-legal `sellers.json` comment field hijacks a naive agent (2 tools, wrong entity, registry pivot skipped) and fails against the defended one (6 tools, correct entity).

**Machine-generated assertions are their own evidence class.** An LLM concluding two handles are one actor is inference over text. It enters at UNCERTAIN, one correlation group per generation. No prior work treats generative output this way.

**DIRECT does not mean direct.** Networks hand publishers a block of `ads.txt` lines to paste, so the same seller IDs appear on tens of thousands of unrelated domains. Accounts are classified by rarity and reciprocity; boilerplate carries **zero** weight. A typical file's 300 records collapse to the 1–5 that identify it.

## What live testing found that 586 synthetic tests did not

Two runs against real domains produced four defects:

- **The corroboration cap was inert.** `band_for` used `min` over a rank where ATTRIBUTED is 0, returning the *stronger* band. The cap did nothing above p=0.55 — precisely its range. The model's central guarantee, broken since the first version.
- **`sellers.json` failed silently for Google** on three counts: wrong URL, file too large for the response cap, and seller names typed as organisations when individual publishers are people.
- **Five identifier kinds were emitted and never pivoted on**, including the `URL` kind holding browser-extension IDs — which point at mandated disclosures.
- **SimHash was not interoperable** with well-known.dev (48-bit vs 64-bit).

## What two external audits found

Twenty-five findings; twenty-three accepted. Four were actively wrong and
self-audit had missed all four — the pattern being that self-audit finds
*conceptual* problems and misses places where **an implementation does not do
what its own comment says**:

- CI failed open (`|| true`) on integration tests, examples and CVE scanning,
  while the docs claimed those gated releases
- the response size cap sliced an already-materialised body, so the documented
  DoS protection did not exist
- the egress config never reached the transport — the manifest would have
  recorded a vantage point no request used
- the agent hard-coded `ORG_NAME` while the canonical classifier existed

All fixed. The **second** audit then found five criticals more consequential
than the first pass's: the evidence verifier accepted material manifest
tampering *and* suffix deletion; `run_case()` created an `EvidenceLog` and never
wired it, so a run making real HTTP requests produced an empty package that
self-verified; a `SAME_AS` claim from the subject's own page could self-grant
the definitional merge privilege by setting `Reliability.AUTHORITATIVE`; and
handle correlation counted six *unrelated* emails as six corroboration points.

Every one reproduced exactly as reported. Responses in `AUDIT_RESPONSE.md` and
`AUDIT_RESPONSE_2.md`.

One correction the second audit made to my own pushback: the "no network I/O in
the core" boundary I used to justify the package split **is currently violated**
by `screenshot.py`, which launches a browser and navigates URLs from inside
`attribution-graph`. Staged.

## Honest limitations

`METHODOLOGY_AUDIT.md` enumerates thirteen. The governing one:

> **Calibration is unvalidated.** Every score is a defensible ordering, not a measured frequency. Of fourteen identified failure modes, **four bias toward overconfidence, two toward misattribution, and one is an unmitigated SSRF gap (DNS rebinding). None bias low.**

Two flaws the audit found in the author's own reasoning:

- Conditional independence across groups was assumed and false — three artifacts of one setup decision scored ATTRIBUTED at p=1.0000. Now corrected structurally; the discounts remain unfitted.
- `DEFAULT_COVERAGE` was fixed from 0.50 to 0.0 on the argument that a guessed figure gives an absence unearned weight — and shipped beside fourteen equally guessed figures. `CoverageBasis` now records provenance: 4 checkable, 10 estimates.

## Notable subsystems

- **Evidence package** — content-addressed captures, hash chain, standalone `verify.py`, RFC 3161 instructions, declaration draft
- **Screenshots** — recorded as *renderings*, never as captures, with element location (selector, DOM path, bounding box, region) and a plain-text log readable without the package
- **Egress** — Oxylabs/Bright Data/Smartproxy/NetNut/Zyte; exit country is part of the evidence; residential exits flagged consent-sensitive
- **Registers** — 43 across ~25 jurisdictions. The UAE is modelled as seven authorities because there is no national register, and flattening that produces confident false negatives
- **Obfuscation** — homoglyph, zero-width and bidi folding, recorded not silently repaired; deliberate obfuscation is itself evidence
- **Security** — SSRF guard (an `ads.txt` line reading `169.254.169.254` would otherwise fetch cloud metadata), ReDoS-bounded regexes, path-traversal refusal, bandit clean

## Status

**Pre-release experimental research codebase.** Not "ready to publish", and not
ready to rely on for a claim about a named person.

Two independent audits. The second reproduced five criticals that the first pass
and self-audit both missed — an evidence verifier that accepted provenance
tampering and suffix deletion, a runner that self-verified an empty evidence
package after making real requests, a definitional merge privilege a
subject-controlled claim could grant itself, and handle correlation scoring six
*different* emails as HIGH-confidence corroboration. All fixed; see
`AUDIT_RESPONSE_2.md`.

The pattern across both audits: self-audit finds conceptual problems and misses
**places where an implementation does not do what its own comment says**. Those
need a reader who does not already believe the comment.

`./VERIFY.sh` runs twelve stages and gates a release. It currently fails on one
check by design: the four LICENSE files are placeholders and must be replaced
before pushing.

The single highest-value next step is the calibration study in `CALIBRATION.md`
— 500+ labelled pairs, three independent label sources, split by case not by
pair, prevalence-corrected. It converts every probability from an ordering into
a measurement and would expose the overconfidence asymmetry if it is real.
