# Response to re-audit (v1.6.0 → v1.7.0)

**Every finding I checked was reproducible.** I verified the five criticals
against the code before changing anything, and each behaved exactly as the
report described. No pushback on any P0 item.

The report's framing is the right one and I am adopting it: the problem is
**assurance mismatch**. Good local implementations existed while the
user-facing execution path did not compose their guarantees end-to-end. Fixing
that was this pass; no features were added.

---

## Verified before fixing

| Finding | Reproduced |
|---|---|
| EA-01 entry hash omits headers/collector/note/body_path | yes — all five unhashed |
| EA-02 suffix deletion verifies | yes — deleted a capture, verifier said PASSED |
| EA-03 runner never wires EvidenceLog | yes — `Fetcher(...)` built with no log |
| EA-04 definitional self-grant | yes — `subject_html` claim merged evil.example into Victim Corp |
| EA-05 unique emails corroborate | yes — 6 different emails → 7 points, HIGH, durable=True |
| EA-09 budget bypassed by redirects | yes — `max_requests` not re-checked per hop |
| EA-10 declared dependence ignored | yes — never gathered in `assess()`, never serialised |
| EA-16 VERIFY.sh absent from repos | yes — existed only at workspace root |

---

## P0 — fixed

**EA-01.** The entry hash now covers a versioned canonical envelope: request
headers, response headers, collector, note, body_path, egress, outcome. Bumping
`ENTRY_SCHEMA` is required to change the field set, so a future field cannot
fall outside it by omission. Four tamper cases are permanent tests.

**EA-02.** The generated verifier recomputes the chain head and compares it to
the declared `manifest_hash`, and reconciles `capture_count`. Deleting the final
capture now fails with an explicit message. The verifier also states what it
**cannot** prove — internal consistency is not provenance, and only an external
anchor establishes that the package was not regenerated wholesale.

**EA-03 / EA-06.** Capture recording and policy evaluation are now transport
invariants: the layer performing the request records it, including refusals and
errors. `run_case()` passes the log and the policy engine into `Fetcher`, and
reconciles fetch count against capture count — a non-empty run producing an
empty package now fails verification rather than reporting `evidence_verified=True`.

**EA-04.** `is_definitional()` requires an engine-recognised registry collector
or source class, matched literally. Reliability is a scalar the claim author
supplies, so keying the model's strongest privilege on it made the carve-out
self-service. The hostile claim now scores UNSUPPORTED and does not merge;
`gleif` retains the exemption.

**EA-05.** A correlation point must connect observations. Identifiers are keyed
by value and counted only when the same normalised value appears on two or more
distinct profiles; singletons are reported in the caveat rather than silently
dropped. The reproduced case is now a permanent test: six profiles, six
different emails → **1 point, INSUFFICIENT**, down from 7/HIGH.

One existing test had encoded the bug — five profiles with five *different*
names and domains, asserting MODERATE. Rewritten to share the identifiers so it
tests the cap it was written for.

**EA-07.** `Fetcher` is constructed from `EgressPool.from_case(scope.egress)`.

**EA-09.** Budget is checked before every physical request including redirect
hops. `max_requests=1` with a 302→200 chain now raises rather than completing at
count=2.

**EA-10.** `assess()` gathers declared classes per canonical group, rejects
conflicting declarations within a group, and passes them through. Serialised in
`Claim.to_dict()`.

**EA-11.** Merge policy moved out of probability space:
`MERGE_LLR_THRESHOLD` in nats, applied to `log_odds`. Renaming the display while
keeping a 0.90 cut on the same unvalidated number would have been cosmetic.

**EA-15.** CI clones sibling repositories before the integration step, so the
gate can actually pass rather than being structurally red.

**EA-16.** `VERIFY.sh` ships in all four repositories. It existed only at the
workspace root while the docs told users to run it.

**EA-17 / EA-18.** Screenshot tests use the declared `browser` marker rather
than a `skipif` alias, so default `addopts` actually excludes them.
`available_renderer()` resolves and stats the Chromium executable instead of
treating package importability as availability. `Fetcher` accepts an injected
resolver, making the transport tests deterministic — mocking HTTP was not
enough, because validation performed real DNS first.

**EA-22.** Stale `net.py` comment corrected. Test counts reconciled: **723
collected, 714 in the deterministic default.**

---

## Accepted, staged, with the reason

**EA-12 — screenshot is a second network stack outside the SSRF boundary.**
Correct, and it also breaks the "no network I/O in the core" argument I used to
justify the package split. `screenshot.py` should move to a capture package
behind the same policy boundary, and browser subresource requests need route
interception. That is a package boundary change plus a sandboxing design, and
doing it badly would be worse than the current documented state.

**EA-13 — `parent_body_sha256` is caller-declared.** Right: Playwright
navigates the live URL independently, so a page changing between fetch and
screenshot yields screenshot B labelled as rendering body A. The fix is to
render the preserved body or hash the browser's actual main-document response.

**EA-14 — screenshot CLI flags are no-ops.** Confirmed. Rather than leave a
flag that does nothing, the flags are staged with the capture path.

**EA-19 / EA-20 / EA-21.** Exception taxonomy narrowing in `Engine`, audit-log
minimisation at the serializer boundary, and operator/hostname metadata as an
explicit choice. All correct, none load-bearing for the P0 assurance story.

---

## On the release framing

I accept the recommendation. This is **not** "ready to publish". `DESIGN.md`
and `PUBLICATION_PLAN.md` now describe it as a **pre-release experimental
research codebase**, and the evidence package is no longer described as
tamper-evident without the qualifier that deletion resistance requires an
external anchor.

The two things that would change that assessment, in order: replace the
LICENSE/OWNER placeholders, and run the calibration study. Everything else on
the P1/P2 list is quality work on a system whose assurances now at least
compose.
