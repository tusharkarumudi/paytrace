# Independent audit — v2.0.0 release candidate

Run against the same surfaces the sign-off audit uses, and by the same method:
**execute production entry points, do not read source**. Reading source is what
produced three repeat findings across earlier rounds.

**Result: two defects found and fixed. 899 tests, `VERIFY.sh` green.**

---

## What I executed

| Check | Method | Result |
|---|---|---|
| Every MCP tool under a live event loop | `asyncio.run(call_tool(...))` for all 4 plus an unknown name | pass |
| Every CLI subcommand | subprocess, real args, checked for tracebacks | pass |
| `asyncio.run` inside any `async def` | AST walk over all four packages | none |
| Real `run_case()` with mocked transport | every `SuiteResult` consumer exercised | **1 defect** |
| Exit codes for all four states | valid / invalid / evidence-fail / incomplete | 0 / 4 / 1 / 3 |
| Evidence package after a real run | `verify_package()` on live output | pass |
| Four-act injection demo | executed | pass |
| Committed traces vs behaviour | `capture_traces.py --check` | current |
| Filesystem containment | ran from a clean cwd, diffed | **1 defect** |
| Shipped case examples | loaded and inspected | pass |
| Wheel package data | `registries.yaml` present in built wheel | pass |
| sdist hygiene | scanned for evidence/audit/cache/env | clean |

## S1 — MCP presented a raw identifier as the conclusion

**Critical.** On a real run, `_top_entity()` returned:

```json
{"conclusion": "seller_id:pubmatic.example/156423", "band": "UNSUPPORTED"}
```

`max(entities, key=len(identifiers))` over singleton clusters returns whatever
sorts first, and `best_label` falls back to the identifier key. An agent would
have relayed a seller ID as the operator's identity — and a conclusion paired
with `UNSUPPORTED` is incoherent on its face.

This is the B2 family exactly: the field mapping was correct, the *values* were
not, and no test had run the tool against a real result.

Fixed: a conclusion is reported only when an entity merged ≥2 identifiers, the
top assessment is above the corroboration floor, and the label is a name rather
than an identifier key. Otherwise `resolved: false` and an explicit instruction
not to present any identifier as the answer.

## S2 — retrieved content written outside the case boundary

**High.** `cache_dir` defaulted to `Path(".eae-cache")` — the process working
directory. Every run scattered subject-retrieved bytes wherever the operator
happened to be, outside the retention and minimisation boundary the case file
defines, and left them there.

Fixed: no CWD default. The runner places the cache under the case output; a bare
`Fetcher` gets a per-process temporary directory. Verified by running from a
clean directory and diffing.

---

## What I could not close

**The hosted release path.** Workflow content is correct, YAML-valid, the
topology fault is fixed and the SBOM is product-only — but only an actual tag
push exercises GitHub's execution. Do a dry run on a throwaway tag.

**The GitHub handle.** `tusharkarumudi` is my substitution for the sentinel and
is now in wheel metadata.

## What I deliberately did not chase

Everything on the auditor's defer list: SHA-pinning, CI restructuring,
calibration, DNS-rebinding pinning, screenshots, exception taxonomy, monorepo.
None affect release safety, and the experimental/beta framing covers them.

---

## Honest limit

I found two defects the last audit did not. I cannot promise a third audit finds
zero — no audit proves absence. What I can say is that both findings came from
executing production paths rather than inspecting them, which is the specific
method that produced every repeat, and both now have regressions attached.
