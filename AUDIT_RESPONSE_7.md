# Response to the full-repository audit — v2.0.0

All eight stop-ship findings closed, each with a behavioural regression against
the artifact or path the auditor examined. Plus D2, D5, D6 and D7 from the
defer list, which were cheap.

**941 tests. `VERIFY.sh` green.**

---

## B1 — and why I got it wrong last time

The auditor is right that this contradicts `AUDIT_RESPONSE_6.md`, and the
mechanism is worth stating plainly: **I fixed the test that checks the sentinel
and left the workflow that greps for it.** The fix and its verification were the
same file, so the test passed by construction while CI stayed deterministically
red on valid production metadata.

All four `ci.yml` files now grep `github.com/OWNER/`, and the regression reads
**the workflow**, not the test.

## B2 — build once

The gate built, checked and clean-installed `dist/*`; the release job then
checked out and built again. That discards the strongest release invariant —
tested == signed == published — and the second artifact never saw the
clean-install gate.

The gate now uploads `dist/` as a workflow artifact and the release job
downloads exactly those files. No checkout, no `python -m build`. The tag check
in the release job now validates the **downloaded wheel's** version rather than
a source file, which is the stronger assertion and also closes D7's duplicate.

## B3 — the manifest authenticated the wrong thing

`manifest_hash` was only the capture-chain head, so `case_ref`, `authorization`,
`fetch_policy` and `environment.tool_version` could be rewritten freely and the
verifier still returned ok — reporting the forged case reference back.

For an evidence-preservation tool those are the load-bearing claims: under what
authority the collection happened, under what policy, with which build. A
verifier that authenticates the bytes but not the circumstances authenticates
the wrong thing.

Added `envelope_digest` over an explicit field list plus the chain head, written
and recomputed by the same function so writer and verifier cannot drift. A
manifest without one is rejected rather than silently accepted.

## B4 — invalid runs produced normal reports

`write_all()` ran unconditionally and the report generator had no status input,
so a run with `result_valid=false` produced an ordinary "Attribution
assessment". Exit codes do not travel with a document once it has been shared.

Markdown and HTML now carry an INVALID / INCOMPLETE / COLLECTION-LIMITED banner
at the top, driven by the same stats the exit code uses.

## B5 — `--no-evidence` changed the meaning of the result

`_report_blocked()` ran only inside the evidence branch, so disabling evidence
capture turned "collection was blocked" into "checked and found nothing". A
fully-blocked run reported `result_valid=true`, `result_complete=true` and no
warning at all.

Blocked reconciliation is now a property of collection. Verified end-to-end:
`--no-evidence` with every host blocked gives `collection_blocked=45`,
`result_complete=false`, and an INCOMPLETE banner in the written report.

## B6 — `"false"` enabled username enumeration

`bool("false")` is `True`, so a quoting choice switched on the sensitive
capability it appeared to disable, silently. `minimize` and
`allow_username_enumeration` now require real YAML booleans; `"false"`,
`"true"`, `0` and `1` are all rejected with an explanation.

## B7 — the report labelled the wrong quantity

The column read "evidence score (nats)" and printed `probability`; the HTML drew
a `probability*100` bar. The project's central caveat is that the logistic
output is uncalibrated, so giving it another quantity's units is a substantive
interpretation error, not a cosmetic one.

Both now print `log_odds`. The HTML bar is a fraction of a labelled nats ceiling
rather than a percentage. The regression parses the generated row and compares
the printed number to the assessment.

## B8 — invalid Cypher, and it was mine

`graph.cypher` emitted `REQUIRE (i.masked(salt) if salt else i.key) IS UNIQUE` —
a Python expression inside Cypher. My own minimisation scrub regex rewrote a
string literal. Now `REQUIRE i.key IS UNIQUE`, with an exact-output regression;
the key is already masked when minimisation is on.

## Deferred items also closed

**D2** Python 3.14 added to the CI matrix. **D5** the temporary cache is removed
on `aclose()` — subject content should not outlive the process. **D6** transport
cleanup moved under `finally`. **D7** duplicate tag check removed.

Still deferred, per the auditor: SHA-pinning (D1), duplicate policy evaluation
(D3), URL policy over cache reads (D4), PEP 639 metadata (D9), and the
architecture items.

---

## The one thing I cannot close from here

**The hosted release path.** Workflow content is correct, YAML-valid, builds
once and publishes the gated artifact — but only a real tag push exercises
GitHub's execution. Do the throwaway-tag dry run the audit asks for, and check
that the published wheel hashes match the `SHA256SUMS` the gate produced.

`tusharkarumudi` remains my substitution for the sentinel and is in wheel
metadata.
