# Self-audit — v1.8.0

Run after three external audits, targeting the two failure classes that
recurred in all of them rather than re-reading the code generally.

**The recurring pattern, stated plainly:** self-audit is good at finding
conceptual problems and bad at finding places where an implementation does not
do what its own comment says, or where a test passes for a reason other than the
one it names. Both need a reader who does not already believe the code. So this
audit was run as checks, not as reading.

---

## What I checked, and how

| Class | Method | Result |
|---|---|---|
| Built-and-never-used (the EA-03 class) | AST walk: locals assigned from a constructor and never read | none found |
| Tests asserting existence not behaviour | grep for `in inspect.getsource` assertions | 1 found, justified (asserts a wiring, paired with a behavioural test) |
| Silent fallbacks | grep `except TypeError` / bare `except Exception` | all now either re-raise, record distinctly, or are documented |
| Unwired runner dependencies | reference-count every constructor local in `run_case` | all referenced ≥4× |
| Version coherence | import all four, compare | aligned |
| Claims in comments | count strong assertions, spot-check the load-bearing ones | see below |

## What it found

**Every capture recorded `collector="fetcher"`.** `_record_evidence` read a
`current_collector` attribute that no production code ever set — the audit named
this and I had not fixed it. A mutable field would also have been wrong:
collectors run concurrently against one shared fetcher, so whichever set it last
would win.

Fixed with a `contextvars.ContextVar` and a `collector_context` manager, wired
into `Engine` so each collector's fetches are attributed to it. Verified: two
fetches under different contexts record different collectors. The robots.txt
lookup attributes to `fetch_policy` rather than to whoever triggered it.

`attribution-graph` imports the context manager lazily and optionally, so the
no-network-I/O boundary that makes its scoring auditable is preserved — it
gains no dependency on the collector package.

**The version drifted twice during this session** (1.7.1 → 1.7.2 → 1.7.1 in
metadata), which is the same unexplained divergence reported in
`AUDIT_RESPONSE_3.md`. It is now set deterministically by pattern substitution
rather than by incrementing whatever was there, and `VERIFY.sh` checks alignment.

## What it confirmed as already correct

Verified behaviourally, not by reading:

- **Audit-log minimisation** is enforced at the serializer. A collector writing
  `email="person@example.com"` produces `min:bc5d6ee4…` in the log.
- **Workstation identity** is not disclosed by default: the manifest environment
  block reads `hostname: (not disclosed)` unless declared.
- **Robots retrieval** consumes budget and is captured, and is exempt from
  policy without disabling SSRF, budget or evidence recording.
- **404s, redirect hops and cache hits** each produce a capture.
- **`EvidenceLog.record` signature mismatch** now raises rather than falling
  back — that fallback had quietly become the normal path.

---

## Non-blocker items from the release audit, now done

**Public language.** `attribution-graph/README.md` no longer promises "a
probability you can defend". `METHOD.md`'s band table no longer maps to ICD 203
estimative language. `handle-correlation`'s sample output no longer prints
`ATTRIBUTED`.

**README version strings** are no longer hand-maintained; they point at
`CHANGELOG.md`, so they cannot go stale.

**Tag ↔ version validation** added to every release workflow. A tag that
disagrees with the packaged version publishes an artifact nobody can trace to a
commit.

**`paytrace run` demoted.** It exercises collectors only and now says so on
stderr and in its help text, so it cannot be mistaken for the unified
evidence/policy contract that `attribution run` provides.

**Python matrix** already covers 3.11 / 3.12 / 3.13 in CI.

---

## Deliberately not done

**Monorepo migration.** The auditor called it a maintenance recommendation, not
a release requirement, and agreed the package boundaries are sensible. Doing it
now would touch every path in the deployment guide for no release benefit.

**Screenshot relocation and browser sandboxing.** The feature is off the release
surface, so the work can happen without release pressure.

**DNS rebinding through proxies.** On the auditor's own defer list, documented
in `SECURITY.md`, and complicated by remote DNS at CONNECT.

**Collector-by-collector `dependence_class` adoption.** The fallback is
conservative, so partial adoption is safe.

**Calibration study.** The claims around it are restrained: no calibrated
probability is asserted anywhere on a public surface.

---

## Current state

**766 tests, 155 of them adversarial.** All twelve `VERIFY.sh` stages pass
except the LICENSE gate, which is the intended failure and the one remaining
release blocker.

The honest summary is unchanged from the audit's own: this is a coherent system
whose assurances now compose end-to-end, held from release by a licensing
decision rather than by a defect.
