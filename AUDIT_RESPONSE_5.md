# Response to the go/no-go audit — v2.0.0 patch

All eight Section 4 blockers are closed, each with a behavioural regression
test. Scope was not broadened: nothing outside the blocker list was changed
except where a fix required it.

**869 tests. `VERIFY.sh` passes all twelve stages.**

---

## The eight

**B1 — release workflow inconsistent.** Two faults, both fatal to the tag path.
A `with: { fetch-depth: 0 }` mapping sat on a `run:` step, which GitHub rejects;
it now sits on the `checkout` action where it belongs. The SBOM was produced as
`sbom.json` and consumed as `sbom.cyclonedx.json`, so signing and upload
referenced an artifact that did not exist — one name now, generation through
publication, asserted by a test that fails if more than one appears.

**B2 — MCP `attribute_domain` was broken.** It read `result.conclusion` and
`result.band`; `SuiteResult` has neither. It would have failed at runtime for
every user while the package suite stayed green.

The root cause is worth naming: the module raised `SystemExit` at import when
the `mcp` extra was absent, so its tests *could only* read source text. The
protocol types are now optionally imported behind lightweight stand-ins, the
logic is importable and tested, and `_top_entity()` reads fields that exist.

There was also a packaging fault underneath it. A top-level `mcp/` directory
**shadowed the real `mcp` package** on `sys.path`, so `from mcp.server import
Server` resolved to this project's own file. The server now lives only inside
the package.

**B3 — MCP safety contract inconsistent.** `explain_ads_txt` performed live
retrieval with only `domain` required, so the advertised authorization control
covered one of two network tools. A control that depends on which tool the model
picked is not structural. Both now require it.

Domain validation was `"/" not in domain and "@" not in domain`, which accepted
IP literals, paths and userinfo — and the value was then interpolated into YAML
text. Now RFC 1123 label syntax with explicit IP-literal rejection, and the case
file is built as a mapping and serialised with `yaml.safe_dump`.

**B4 — `minimize: true` did not minimize at rest.** `write_all()` emitted a raw
`investigation_graph.json` beside the minimized copy, and the FTM, Cypher, HTML
and markdown exports were never minimized at all. A raw export beside a
minimized one is a raw export.

Under `minimize`, the minimized form is now the **canonical** export. Masking
keys was insufficient on its own: the same values reappeared in `source_url`, in
report prose and in Cypher literals, so a value-aware scrub runs over the
rendered text of every artifact — the same approach the audit log uses, and for
the same reason. `Entity.attributes` are masked recursively.

**B5 — invalid runs looked successful.** `result_valid` / `result_complete` were
computed inside the `if evidence:` branch, so a `--no-evidence` run omitted them
entirely and a caller checking `is not False` treated a failed run as fine. They
are now computed from the collection itself.

Exit codes are defined and tested: **0** valid and complete, **1** evidence
verification failed, **3** incomplete, **4** invalid.

**B6 — budgets could hang or truncate silently.** `concurrency: 0` built a
zero-permit semaphore. `budget.max_nodes: 0` loaded cleanly because nothing read
it at load time, then truncated the search to nothing while the result still
reported complete. Every budget field is now validated at load whether or not
the constructor consumes it, and node-budget truncation sets
`result_complete=false`.

**B7 — `OWNER` placeholders.** Replaced across 29 files, including the runtime
`User-Agent` strings. Verified in the built wheel metadata, not just the source.

**B8 — redirect-to-error lost the final URL.** The success path was corrected
last round and the error path was not, so a 302 → 404 recorded the 404 against
the starting URL. Fixed and tested across 301/302/307/308.

**Legal wording.** The Bharatiya Sakshya Adhiniyam 2023 replaced the Evidence
Act on 1 July 2024; s.65B became s.63. Corrected, with an explicit statement
that the package produces material a certificate can describe and does not
itself constitute compliance.

---

## Final gate

Per Section 7: full deterministic suite green, new blocker regressions green,
every wheel and sdist built and `twine`-checked, all four installed into a clean
virtual environment, imports and all five console scripts smoke-tested, wheel
metadata checked for placeholders, tag/version validation wired into the release
workflow.

One note on that last item: workflow *content* is now correct and YAML-valid,
but as the audit says, only a real tag push exercises the GitHub-hosted path. I
have not published one.

## What I did not touch

Everything on the defer list: monorepo conversion, screenshot architecture,
scoring redesign, DNS rebinding pinning, calibration, collector exception
taxonomy. The release position remains **experimental / beta**, with the
scoring model stated as evidence strength rather than calibrated probability.
