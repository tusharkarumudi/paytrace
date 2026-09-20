# Response to the sign-off audit — v2.0.0

All seven blockers closed, each with a behavioural regression through the real
entry point. **896 tests. `VERIFY.sh` green.**

The recurring failure the auditor identified — testing an adjacent surface
rather than the production path — is the thing I most needed to correct, and it
explains all three of the repeats.

---

**B1 — MCP failed inside the event loop.** The handler is `async` and called
synchronous `run_case()`, which uses `asyncio.run()` internally: a nested-loop
`RuntimeError` on every call. Last round I fixed the fields it read and never
invoked it under a loop. Now `asyncio.to_thread(run_case, ...)`, and the test
awaits the real handler inside a running loop.

**B2 — `--concurrency 0` still deadlocked.** Case-file validation was the wrong
boundary; the CLI flag is a separate input path and reached
`asyncio.Semaphore(0)`. Validation moved to the `Engine` constructor — the one
boundary every entry point crosses — with a CLI guard that fails fast at exit 2.

**B3 — runtime truncation reported complete.** `max_runtime_s` could stop
traversal with frontier work queued while `result_complete` stayed true. Now
sets `runtime_exhausted` and clears completeness, with the remaining frontier
size recorded in the audit trail.

**B4 — robots 5xx permitted retrieval.** RFC 9309 §2.3.1 distinguishes
*unavailable* (4xx: no rules apply) from *unreachable* (5xx or network failure:
assume complete disallow). Both returned `None` and `None` meant proceed — so a
target serving 503 on `/robots.txt` got crawled under a policy named `respect`.
An operator reading that policy name had been told something untrue.

| | robots 200 | 404 | 503 | network fail |
|---|---|---|---|---|
| respect | BLOCK | fetch | **BLOCK** | **BLOCK** |
| record | fetch | fetch | fetch | fetch |

The cache is now keyed by `(scheme, host)` too, since `http://` and `https://`
robots.txt are separate resources.

**B5 — release topology.** The placeholder check matched `"OWNER"`, which also
matches `OWNERDOMAIN` (a real IAB field) and would have flagged the substituted
handle. It now targets the sentinel `github.com/OWNER/`, with an explicit
allow-list for the files that assert on it. Sibling checkout moved ahead of every
sibling-dependent test step in all four workflows.

**B6 — encoded identifiers survived minimisation.** `Jane Doe` persisted as
`Jane%20Doe` in a URL provenance field. The scrub now covers the canonical forms
the pipeline itself produces — percent-encoded, `quote_plus`, case variants,
separator substitutions — because minimisation that matches one spelling
protects the spelling rather than the person.

**B7 — SBOM was not product-only.** The generator was installed alongside the
released wheel and then asked to inventory that environment, so `cyclonedx-bom`
and its closure appeared in the product SBOM. Two environments now: the wheel in
`/tmp/product`, the generator in `/tmp/sbomtool`, and a check that **fails the
build** if tooling appears in the output.

---

## Sign-off criteria (Section 8)

| Criterion | State |
|---|---|
| MCP executes in the real async loop | closed, tested under a live loop |
| Every concurrency entry point rejects < 1 | closed at the engine boundary |
| Runtime exhaustion is machine-detectable | `result_complete=false` |
| robots `respect` fails closed on 5xx/network | closed, 4xx preserved |
| Sibling checkout precedes dependent tests | closed in all four workflows |
| Minimized exports free of raw and encoded forms | closed |
| SBOM reflects the product closure | closed, with a failing guard |
| Regression suite green | 896 tests |
| Wheels install and import in a clean venv | verified, all five console scripts |

## The one thing I cannot close from here

Workflow *content* is correct and YAML-valid, and the topology fault is fixed.
But as the audit says, only an actual tag push exercises the hosted path.

**Do a dry run on a throwaway tag before the public one.** That is the last
unverified step, and it is unverifiable from an archive.

Also: `tusharkarumudi` is my substitution for the sentinel and it is now in
published metadata. Change it if that is not your handle.
