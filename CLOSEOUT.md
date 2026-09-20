# Close-out — v2.0.0

Build `20260920-034606` · **1175 tests** · `VERIFY.sh` green.

Everything below was re-verified from the shipped tarballs, not a working tree.

---

## Verified

| Check | Result |
|---|---|
| Full gate, all four together | 1175 tests, 12 stages pass |
| Each repo alone, as its own CI clones it | graph 202 · paytrace 419 · handle-corr 64 · suite 343+156 skip |
| Workflows: gated, SHA-pinned, `pypi` env, OIDC, dependabot | no issues |
| Third-party actions | only `pypa/gh-action-pypi-publish` — the Trusted Publishing path |
| Versions, LICENSE, citations, docs, script modes | no issues |
| Build + `twine check` + clean-venv install | 4/4, all 5 console scripts |
| Security controls, exercised not inspected | 11/11 |
| `minimize: true` — every form, every length, exports + audit | no leaks |
| Docs consistency | 9/9 |
| Conference deck + runbook | 7 slides, 7 notes, all beats covered |

**Security controls proven at runtime:** socket pinned to the validated address ·
malformed port → controlled rejection · metadata IP blocked · `audit.jsonl` 0600 ·
evidence dir 0700 · manifest forgery rejected by *both* verifiers · quoted
`"false"` rejected · concurrency 0 rejected at both entry points · MCP refuses
without authorization.

---

## To publish

```bash
# 1. Confirm you are on the current tree
grep "^build:" BUILD_ID                      # 20260920-034606
grep -c "gh release create" .github/workflows/release.yml   # >= 1
grep -m1 '^version' pyproject.toml           # 2.0.0, not 2.0.0rc1

# 2. Push
GH_OWNER=tusharkarumudi GIT_EMAIL=tusharkarumudi@gmail.com ./PUSH.sh

# 3. Tag, in dependency order, waiting for each to reach PyPI
cd attribution-graph      && git tag v2.0.0 && git push origin v2.0.0
cd ../paytrace            && git tag v2.0.0 && git push origin v2.0.0
cd ../handle-correlation  && git tag v2.0.0 && git push origin v2.0.0
cd ../attribution-suite   && git tag v2.0.0 && git push origin v2.0.0
```

If `v2.0.0` already exists locally it points at an older commit — `PUSH.sh`
warns, and `PUBLISHING.md` §6 has the move sequence.

**Prerequisite done once:** PyPI Trusted Publishing configured for all four
(`PUBLISHING.md` §4), and a `pypi` environment created in each GitHub repo.

---

## Guards that will stop you making a mistake

`PUSH.sh` refuses to run on: a missing `VERIFY.sh`, a placeholder LICENSE or
`OWNER` URL, mismatched versions, an owner that does not match `GH_OWNER`,
untracked investigation artifacts, a missing `workflow` token scope, or a
**pre-release version left in place after a rehearsal**. It warns on a tag that
points behind HEAD, and diagnoses a divergent remote rather than printing a raw
git error.

The release gate refuses to publish a tag whose version does not exactly match
the packaged one, audits the third-party dependency closure, and publishes the
artifact it built rather than rebuilding.

---

## Open, and why

**The hosted release path.** Only a real tag exercises GitHub's execution of the
release job. The workflow content is correct and the rehearsal covered the gate;
the publish step itself has not run.

**Node 20 action bumps.** A deprecation warning, not a failure. `dependabot.yml`
ships in all four, so `checkout@v5` and `setup-python@v6` arrive as reviewed
pull requests. Hand-writing those SHAs would be a supply-chain risk, not a
convenience.

**Calibration.** The governing limitation. Bands are an ordering, not a
frequency. Stated in `METHODOLOGY_AUDIT.md`, the README, the citations, the
reports and the MCP responses. Unresolved by design — a study, not a patch.

---

## Deliberately not done

Monorepo conversion · moving `screenshot.py` out of the inference package ·
scoring redesign · duplicate policy evaluation · URL policy over cache reads ·
PEP 639 metadata. None affect release safety, and the experimental/beta framing
covers them.
