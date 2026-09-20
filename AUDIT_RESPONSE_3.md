# Response to release-readiness audit (v1.7.0 → v1.7.1)

**Decision accepted: HOLD was correct.** Four of the five mandatory blockers are
fixed; the fifth is licensing, which needs your decision rather than a code
change.

One finding I have to report before the substance.

---

## A discrepancy in the artifacts I shipped

The auditor tested the v1.7.0 tarballs. Reproducing their findings, I discovered
the working tree contained fixes for RB-01, RA-02 and RA-03 that were **not in
the tarballs I shipped**. I did not make those edits during the session that
produced v1.7.0.

I cannot explain the divergence, and for a tool whose entire purpose is evidence
integrity that is worth stating plainly rather than quietly reconciling. What I
have done:

- treated the **tarballs** as authoritative, since that is what was audited;
- re-run every one of the auditor's reproductions against the current tree
  rather than assuming any fix was real;
- verified each remaining fix myself before claiming it.

Concretely: RB-01, RA-02 and RA-03 were already correct in the tree and I
confirmed them. RB-02, RB-03, RB-04, RA-01 and RA-04 were **not** fixed and I
fixed them in this pass.

---

## RB-02 — my own regression, and worse than reported

The auditor found `MERGE_LLR_THRESHOLD = 13.71` nats compared against
`a.probability`, which cannot exceed 1.0. Correct, and it was my fix from the
previous round: I renamed the constant's units without changing what it was
compared to, converting a tuning question into a correctness bug that failed
silently in the quiet direction.

The constant was also wrong on its own terms. `Assessment.log_odds` already
includes the prior, so adding `|log(PRIOR_ODDS)|` double-counted it. The
posterior threshold preserving the old 0.90 boundary is `log(0.9/0.1) = 2.197`.

**But fixing the threshold did not restore merging**, and this is the more
consequential finding. The resolver only scored directly-claimed
subject→object edges. Two domains sharing an identifier were **never assessed
as a pair at all** — the toolkit's canonical case. Each leg had one correlation
group, the corroboration rule correctly refused to merge on one group, and the
two-group evidence that actually existed was never pooled.

So no threshold could have helped: inferential merging had never worked.

`resolve()` now generates co-reference candidates — subjects sharing an object —
and pools both legs, which is the standard record-linkage construction.
Measured: two domains sharing two identifiers now merge at log_odds 8.89 with
two independent groups; sharing one identifier still does not merge.

## RB-03 — the constraint passed for the wrong reason

The transitive must-not-link check appeared to pass in my first run. It passed
because nothing merged at all. With merging restored, the real behaviour is
correct: A~B merges, and B~C is **rejected** because the union would place A and
C in one cluster against an explicit contradiction.

That is a lesson worth recording: a constraint test that passes while the
mechanism it constrains is disabled proves nothing.

## RB-04 — verifier no longer executes package code

`attribution verify` ran the `verify.py` inside the evidence directory. An
evidence package is untrusted input by definition. New
`attribution_graph.verify` reads the manifest as data, refuses `body_path`
values escaping the package, and the CLI uses it. Tested with a planted script
that writes a marker file: exit 0, marker absent.

The generated standalone `verify.py` still ships — a dependency-free checker a
reader can inspect in full has real value — and the CLI now prints a note saying
it was *not* executed and why.

## RB-05 — licensing

Unresolved, and not something I should decide. All four LICENSE files remain
placeholders while `pyproject.toml` asserts Apache-2.0, so the built metadata
makes a claim the shipped file does not support. `VERIFY.sh` fails on this by
design. ~20 files still carry `github.com/tusharkarumudi/`.

---

## RA items

**RA-01 — evidence completeness.** 404s and redirect hops were already recorded
in the tree; I verified both. The cache case was not: a second run consumed
retrieved content and produced a package with zero captures that verified
clean. Cache hits now emit a capture with `outcome="cache"` carrying the body,
so the digest still commits to what was used and a reviewer can see the bytes
were not fetched during that run.

**RA-04 — provider/network mismatch.** `provider: oxylabs` with
`network: datacenter` was accepted and routed to `pr.oxylabs.io`, the profile's
own documented *residential* endpoint, while recording
`consent_sensitive: false`. Provenance and safeguard wrong at once. Profiles now
declare which networks they serve and a contradicting label is rejected.

**RA-06 / 8.3 / 8.4 — screenshots.** Taken off the release surface.
`--screenshots` now exits 2 with an explanation rather than being silently
accepted and doing nothing. Kept as an explicit error rather than removed so a
user with it in a script learns why.

---

## Phase D gate

All six tests the auditor specified now exist and pass:

1. real `PolicyEngine` + real `Fetcher` across respect / record / ignore
2. resolver positive merge — two independent groups, non-definitional
3. resolver cluster constraint — A~B, B~C, A!~C
4. verifier safety — planted script not executed
5. evidence completeness — 404, redirect, cache
6. case egress — survives `load()`, reaches transport, mismatch rejected

Writing (1) surfaced a further defect in my own test: a shared cache directory
served mode 2 from mode 1's fetch, so the assertion passed for the wrong reason.
Each mode now gets its own cache.

**739 tests collected, 739 passing in the deterministic default.**

---

## Still open, deliberately

DNS rebinding through remote proxies; moving `screenshot.py` out of the
inference package; collector-by-collector `dependence_class` adoption; the
calibration study. All are on the auditor's own defer list, and the claims
around them are restrained accordingly.

The remaining release gate is licensing, which is yours.
