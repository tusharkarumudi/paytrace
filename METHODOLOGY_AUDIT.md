# Methodological audit

An adversarial read of this toolkit, written as if by a reviewer with no stake
in it. It records what the method gets right, where it falls short, what has
been fixed, and what a user should not rely on.

The short version: **the architecture is sound and the parameters are not
measured.** Every probability the system emits is a defensible ordering. None of
them is a validated frequency. That distinction governs everything below.

---

## 1. What holds up

**Provenance is first-class, not bolted on.** Every claim carries collector,
source URL, retrieval time, reliability tier and correlation group. Three
distinct types (`Identifier`, `Claim`, `Entity`) make it structurally impossible
for a consumer to mistake an inference for an observation. Most attribution
tooling collapses these into graph nodes and loses the distinction permanently.

**Selectivity is measured rather than asserted.** Evidence weight derives from
`log(1/selectivity)` against observed holder counts. The model rates a unique
analytics ID near 14 nats and a shared CDN IP near zero *without being told what
a CDN is*. Hand-tuned weight tables cannot do this and go stale silently.

**Corroboration is structural.** `GROUP_CAP < |log(PRIOR_ODDS)|` means no single
inferential correlation group can cross the merge threshold whatever its
strength. This is arithmetic, not analyst discipline, and it survives deadline
pressure in a way convention does not.

**Absence is typed.** "Not checked", "checked and absent" and "expected absent"
are different claims with different weights. Reporting them identically is how
"no record found" becomes a finding it never was.

**Untrusted input is the default assumption, correctly.** The data collected is
authored by the entity under investigation. Treating that as the normal case
rather than an edge case is the right frame, and the four guard layers follow
from it. Two of them (provenance tiering, plan invariants) hold structurally
rather than heuristically.

**Filters demote rather than drop.** A non-probative edge stays visible with its
reason. Deleting it would make an analyst believe the relationship was never
observed — a false negative introduced by the presentation layer.

---

## 2. Where it falls short

### 2.1 Calibration is unvalidated — the governing limitation

The bands, the prior, the caps and the decay constant are principled and
**unfitted**. No labelled corpus has been scored. So:

- `p = 0.989` means "this ranked above other links", not "989 of 1000 such
  links are real"
- ICD 203 language (`almost certainly`) is attached by a mapping table nobody
  has validated against how analysts read it
- The confidence figures would not survive a Daubert challenge, and the
  toolkit says so in three places

Everything else in this section is downstream of this one. `CALIBRATION.md` has
the protocol; it is issue #1 and unstarted.

### 2.2 Conditional independence — fixed structurally, not measured

**The flaw.** Correlation groups stop evidence stacking *within* a source. The
model then sums log-likelihood ratios *across* groups, which assumes conditional
independence given the hypothesis. It frequently fails: an operator installing
one stack emits an analytics tag, a favicon, a theme fingerprint and response
headers in a single action. Four groups, one decision.

Measured before the fix: three such artifacts on one page scored **ATTRIBUTED at
p = 1.0000**. The same failure the correlation-group mechanism exists to
prevent, one level up, biasing toward overconfidence on exactly the evidence an
analyst is most likely to have.

**What was done.** `dependence.py` assigns groups to dependence classes. Within
a class, evidence aggregates sub-additively; across classes, full addition. The
corroboration requirement now counts distinct classes, not raw groups, so one
decision can no longer satisfy a two-group rule.

**What remains wrong.** The discount factors (0.15–0.40) are unfitted, and the
class boundaries are judgement calls. Is enrolling with an ad system the same
decision as installing analytics? Sometimes. The correction bounds the worst
case; it does not produce a correct magnitude.

### 2.3 Coverage figures were guesses presented as measurements

An internal inconsistency worth naming plainly. `DEFAULT_COVERAGE` was corrected
from 0.50 to 0.0 on the argument that *a guessed figure gives an absence
unearned weight* — and that fix shipped beside a table of fourteen equally
guessed figures (0.98, 0.95, 0.99, 0.85 …) formatted as though measured.

Now every figure declares a `basis`. Four rest on something checkable
(statutory registers, one published figure). **Ten are author estimates.** The
numbers did not change; what changed is that a reader can discount them.

### 2.4 The prior is global, and the evidence is selected

`PRIOR_ODDS = 1e-5` is one constant for all pairs. But base rates differ
enormously by context: two domains sharing an ads.txt seller record have a far
higher prior of common control than two domains drawn at random.

Worse, the evidence reaching the model is **selected because it looked
promising** — an analyst pivots on a shared identifier precisely when it seems
distinctive. Applying a population prior to a selected sample overstates the
posterior, and nothing currently corrects for it. A context-conditional prior is
the right fix and is not implemented.

### 2.5 Selectivity is estimated from a biased corpus

Holder counts come from a Tranco-style crawl, which skews to large sites. A
small operator's identifiers appear artificially unique because the corpus does
not cover their neighbourhood — so selectivity is **overestimated** and
confidence **overstated**, systematically and in the dangerous direction.

The CLI warns when no corpus is supplied. It does not warn that the supplied
corpus may not cover the target's segment, which is the more common and more
misleading case.

### 2.6 The constants are arbitrary at the margin

| Constant | Value | Basis |
|---|---|---|
| `PRIOR_ODDS` | 1e-5 | order-of-magnitude judgement |
| `GROUP_CAP` | 8.0 | chosen to sit below the prior |
| `DEFINITIONAL_GROUP_CAP` | 20.0 | chosen to clear it |
| `MIN_INDEPENDENT_GROUPS` | 2 | convention |
| `ALPHA` (Laplace) | 0.5 | Jeffreys prior, defensible |
| Decay half-life | — | no empirical basis for how fast an identifier association decays |
| Dependence discounts | 0.15–0.40 | judgement |

The *inequality* between the first two is load-bearing and tested. The *values*
are not fitted. `ALPHA = 0.5` is the only one with a principled derivation.

### 2.7 Name classification is heuristic and culturally uneven

`classify_seller_name` decides person-vs-organisation from legal-form tokens and
token counts. It gets `HOÀNG PHÚ LINH` right. It will misclassify:

- companies whose names carry no Western legal form (common in China, Japan,
  Indonesia)
- individuals using mononyms or a single family name
- trading names that read like personal names

The error rate is **unmeasured**, and a misclassification routes the
investigation to the wrong registry class — producing a "checked, no match" line
that is a category error rather than a finding.

### 2.8 The injection demo is a simulation

`ScriptedBrain` models instruction-following behaviour deterministically. This
is documented, and `--brain llm` reproduces it with a real model. But the
headline result on stage comes from a stand-in, and a reviewer is entitled to
discount it accordingly.

More importantly: the guards have never been tested against an **adaptive**
adversary who has read the source. Layers 3 and 4 hold structurally, so this
matters less than it would otherwise — but layer 1 (pattern detection) loses to
any paraphrase, and that is asserted rather than demonstrated.

### 2.9 No end-to-end evaluation against ground truth

Every test uses fixtures. Two live runs (`snapvn.com`, `instavisor.net`) found
four bugs the 586-test suite missed, which is evidence *for* the value of real
evaluation and *against* the sufficiency of what exists. There is no case set
with known answers, so nobody — including the author — knows the system's
end-to-end error rate.

### 2.10 Nine catalog entries claim automation that does not exist

INPI, KVK, ACRA, ASIC, Canada, NZ, Open Ownership, RoE, EUIPO are marked
automatable with no collector behind them. A report saying "checked and found
nothing" must mean the source was queried.

### 2.11 Screenshots are renderings and cannot be verified as captures

The evidence package hashes wire bytes, so a reviewer can confirm the file they
hold is the file that was served. A screenshot admits no such check: it is one
browser's output at one viewport at one moment, and re-running it tomorrow
produces a different image from the same URL.

The implementation labels every screenshot a derived rendering, chains it
separately, and links it to the body hash it rendered. That is the right
structure and it does not make a screenshot verifiable. Treat it as
corroborative context, not as the artifact.

Two narrower points. The element locations depend on JavaScript executed inside
a page the subject controls — the locator script only reads, but a hostile page
could in principle influence what it reports, and that has not been red-teamed.
And full-page capture of a JavaScript-heavy site is timing-dependent: a slow
third-party resource can produce a screenshot of a partially rendered page with
nothing marking it as incomplete.

### 2.12 Proxied captures are attributable only as far as the proxy is honest

Recording the exit country makes a capture reproducible in principle. It does
not make the recording true. The tool asks the provider for an exit in a country
and records what it asked for; `verify_egress_country()` checks an observed
address against that request, but the geolocation of an IP is itself an
estimate, and a provider that silently substitutes a different exit produces a
capture attributed to a vantage point it never used.

Residential and mobile networks add a second problem the tool cannot solve. The
exit is a real person's connection. Consent is commonly obtained by bundling an
SDK into a free application, and whether that constitutes meaningful consent is
contested. The tool records the network type in the manifest and the declaration
draft so the choice is visible; it does not make the choice defensible.

A third, narrower point: geo-divergence detection compares response bodies, and
many sites vary trivially by request (CSRF tokens, timestamps, rotated ad
creatives). A naive hash comparison will report divergence that means nothing.
The current implementation does not normalise before comparing, so **divergence
findings need human review before they are treated as evidence.**

### 2.13 Register coverage is now honest and still thin

Modelling the UAE as seven authorities rather than one row removes a class of
false negative. It does not add coverage: none of the seven is automatable, most
have no name search, and several answer only from inside the jurisdiction.

So the improvement is epistemic rather than practical. A report can now say
"checked DIFC and ADGM, did not check the five emirate authorities" instead of
implying a national search happened. That is a real gain — but a user wanting an
answer about a UAE entity still has to do the work by hand, and 34 of 43
registers remain non-automatable.

### 2.14 An external audit found four defects this document missed

Worth recording, because it bounds how much weight to put on self-audit.

An independent review of the repository as a system — not module by module —
found four things that were actively wrong and that this document, written by
the author, had not caught:

- **CI failed open.** `|| true` on integration tests, examples and dependency
  scanning, while the docs claimed those gated releases.
- **The response size cap did not work.** It sliced a fully-materialised body,
  so the documented DoS protection did not exist.
- **The egress configuration did not control transport.** The manifest would
  have recorded a vantage point never used — fabricated provenance.
- **The agent path hard-coded `ORG_NAME`** while the canonical classifier
  existed, the exact drift this document claims elsewhere to have fixed.

All four are corrected; see `AUDIT_RESPONSE.md`. The pattern is worth naming: a
self-audit is good at finding *conceptual* problems (this document found the
conditional-independence flaw and the coverage-provenance inconsistency) and
poor at finding places where **an implementation does not do what its own
comment says**. Those need a reader who does not already believe the comment.

---

## 3. Failure modes a user should expect

| Situation | What happens | Direction of error |
|---|---|---|
| No corpus index | Every identifier looks unique | **Overconfident** |
| Corpus does not cover the target's segment | Selectivity overestimated | **Overconfident** |
| Several artifacts of one setup decision | Partially corrected by dependence classes | Overconfident, reduced |
| Evidence selected because it looked promising | Population prior applied to a selected sample | **Overconfident** |
| Individual publisher, non-Western name | May route to corporate registries | False dead end |
| Boilerplate ads.txt | Handled: zero weight | Correct |
| Planted identifier | Handled: demoted, not deleted | Correct |
| Operator behind Cloudflare | Origin concealed, labelled as such | Correct |
| Absence from a coverage-less source | Zero weight | Correct |
| Screenshot of a slow-loading page | May capture a partial render, unmarked | **Misleading** |
| Proxy silently substitutes an exit | Capture attributed to a vantage point it never used | **Misattributing** |
| Trivial per-request variation (tokens, ad rotation) | Reported as geo-divergence | **False positive** |
| Host re-resolves between validation and connection | SSRF guard bypassed (DNS rebinding) | **Unmitigated, documented** |
| Entity in a federated jurisdiction | Absence from one member register is not absence | Correct, now stated |

**Four of the thirteen bias toward overconfidence, and two more toward
misattribution.** None bias toward
under-confidence. That asymmetry is the single most important thing for a user
to know, and it is a direct consequence of §2.1: without calibration there is
nothing to catch a systematic upward bias.

---

## 4. What would change the assessment

In order of value:

1. **Calibrate.** 500+ labelled pairs, three independent label sources, all
   three negative kinds, split by case not by pair, prevalence-corrected. This
   converts every probability from an ordering into a measurement and would
   expose the overconfidence bias in §3 if it is real.
2. **Fit the dependence discounts** on the same corpus. They are currently the
   least-justified numbers in the system.
3. **Context-conditional priors.** A pair reached via a shared seller ID should
   not carry the same prior as a random pair.
4. **Measure the name classifier** against a multilingual labelled set.
5. **Corpus coverage diagnostics.** Report what fraction of the target's
   neighbourhood the corpus actually contains, so §2.5 is visible per-run.
6. **Adaptive red-team** of the injection guards by someone with the source.
7. **A ground-truth case set**, even ten cases, with known answers.
8. **Normalise before comparing** in geo-divergence, so token and ad rotation
   stop producing false positives.
9. **Verify the exit on every request**, not once per run, so a mid-run
   substitution is caught rather than inferred later.

---

## 5. Honest summary

This is a well-architected instrument with unmeasured parameters. Its
distinguishing property is not accuracy — that is unknown — but that it is
**auditable**: every number traces to a claim, every claim to a source, every
constant is named in one place, and the limitations are enumerated rather than
buried.

For an analyst, that makes it a better tool than one which emits a confident
number with no provenance. For a court, a regulator, or a published claim about
a named person, **it is not yet sufficient**, and the calibration study is what
stands between the two.

Use the bands as an ordering. Read the negative evidence. Check whether a
corpus was supplied. And treat any conclusion about a natural person as a lead
until something statutory corroborates it.
