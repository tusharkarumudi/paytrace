# Publishing guide

How to get v2.0.0 from this archive onto GitHub and PyPI.

Read it once before starting. Two steps are ordered for reasons that are not
obvious — Trusted Publishing must be configured *before* the first tag, and the
four packages must publish in dependency order.

**Time:** about 45 minutes, most of it waiting for CI.

---

## 0. Before you start

You need:

- a GitHub account, and the [GitHub CLI](https://cli.github.com) (`gh auth login`)
- a [PyPI](https://pypi.org) account with 2FA enabled (required for publishing)
- Python 3.11+ locally

Unpack the four archives so they are siblings, with `VERIFY.sh` beside them:

```
attribution/
  VERIFY.sh
  PUSH.sh
  attribution-graph/
  paytrace/
  handle-correlation/
  attribution-suite/
```

```bash
tar xzf attribution-graph.tar.gz   # and the other three
cp attribution-graph/VERIFY.sh attribution-graph/PUSH.sh .
chmod +x VERIFY.sh PUSH.sh         # archives routinely lose the exec bit
```

The layout matters. `VERIFY.sh` and the CI integration step both expect the
packages to be siblings.

**Run the `chmod`.** Zip and some transports normalise modes to `0600`, and the
instructions below invoke `./VERIFY.sh` and `./PUSH.sh` directly. `PUSH.sh`
restores the bit on `VERIFY.sh` if it can, but it cannot restore its own.
`bash PUSH.sh` also works if the bit is lost.

## 1. Decide your GitHub handle, and put it in the metadata

The archive ships with `tusharkarumudi` substituted for the placeholder. **If
that is not your handle, change it now** — before pushing, before configuring
Trusted Publishing, and definitely before tagging. It appears in published wheel
metadata, and Trusted Publishing matches on the repository path.

```bash
cd attribution
OLD=tusharkarumudi
NEW=your-handle

grep -rl "github.com/$OLD" --include="*.toml" --include="*.md" --include="*.cff" . \
  | xargs sed -i "s|github.com/$OLD|github.com/$NEW|g"

grep -rn "github.com/$OLD" . | head    # should print nothing
```

## 2. Verify before you push

```bash
./VERIFY.sh
```

Twelve stages: lint, bandit, unit tests, cross-package integration, adversarial
regressions, version alignment, examples, the injection demo, artifact hygiene,
secrets, ownership, build, clean-venv install.

**It must be green.** `PUSH.sh` refuses to run at all if `VERIFY.sh` is
missing — it used to print "skipping" and carry on, which turned the pre-push
gate into a no-op. A copy ships inside each package; put one at the workspace
root.
If a stage fails, fix it — do not push past it, because the release workflow
runs the same checks and will simply fail later at greater cost.

## 3. Push to GitHub

> **If you get `Authentication failed` after typing your password:** that is
> expected and your password is not wrong. GitHub stopped accepting account
> passwords for Git operations in **August 2021**, but the HTTPS prompt still
> asks for one. Being logged in to `gh` is not enough on its own — git has to
> be told to use those credentials:
>
> ```bash
> gh auth setup-git
> ```
>
> `PUSH.sh` now runs this for you. If your environment blocks credential
> helpers, use SSH instead:
>
> ```bash
> gh auth refresh -h github.com -s admin:public_key   # once
> GIT_PROTOCOL=ssh GH_OWNER=your-handle GIT_EMAIL=you@example.org ./PUSH.sh
> ```
>
> If you prefer a Personal Access Token, it goes in the **password** field (not
> the username) and needs **both** the `repo` and `workflow` scopes:
> <https://github.com/settings/tokens>

> **If you get `refusing to allow an OAuth App to create or update workflow`:**
> these repositories ship `.github/workflows/`, which GitHub protects behind a
> separate token scope. `gh auth login` does not grant it by default.
>
> ```bash
> gh auth refresh -h github.com -s workflow
> ```
>
> `PUSH.sh` now checks for this scope before it commits anything, so you should
> not hit it. If you do, nothing is lost — the script is idempotent and resumes
> from the repository that failed.

> **If you get `! [rejected] main -> main (fetch first)`:** that repository name
> already exists on GitHub with different content. Since these package names
> were used at `0.6.0`, the usual cause is the earlier release of the same
> project. Look before you overwrite:
>
> ```bash
> cd <repo>
> git fetch origin
> git log --oneline origin/main | head -20
> ```
>
> If the file names look like **this project at an earlier version** — the
> usual case — do not rebase. Two unrelated histories of the same files
> conflict `add/add` on every file, and resolving them by hand gains nothing
> because v2.0.0 supersedes all of it.
>
> Preserve the old history on a branch, then replace `main`:
>
> ```bash
> git fetch origin main
> git branch pre-2.0.0 FETCH_HEAD
> git push origin pre-2.0.0
> git push --force-with-lease origin main
> ```
>
> `--force-with-lease` rather than `--force`: it refuses if someone pushed since
> your fetch, so you cannot clobber a change you have not seen. The branch keeps
> the old commits reachable, so this stays reversible.
>
> Only if the remote holds genuinely **different** work worth merging:
>
> ```bash
> git pull --rebase --allow-unrelated-histories origin main
> # resolve conflicts, or back out with: git rebase --abort
> ```
>
> Then re-run `PUSH.sh` to finish the remaining repositories.


```bash
GH_OWNER=your-handle GIT_EMAIL=you@example.org DRY_RUN=1 ./PUSH.sh   # rehearse
GH_OWNER=your-handle GIT_EMAIL=you@example.org ./PUSH.sh             # do it
```

It creates the four repositories if absent, commits, and pushes `main`. It is
idempotent — re-running adds a commit rather than clobbering.

It refuses to proceed if the LICENSE is still a placeholder, if `github.com/OWNER/`
survives anywhere, if the four versions disagree, if project URLs do not match
`GH_OWNER`, or if untracked investigation artifacts are lying around.

**No tag yet.** Tagging is what publishes.

Confirm normal CI is green on all four before continuing. If the placeholder
gate is red, step 1 was incomplete.

## 3b. Enable SHA-pinning policy on each repository

The workflows pin every Action to a full commit SHA. Enforce it at the
repository level too, so a future edit cannot reintroduce a mutable tag:

**Settings → Actions → General → "Require actions to be pinned to a
full-length commit SHA"**

The release job holds `contents: write` and `id-token: write`, so the Actions it
runs are inside the trust boundary for signing and publishing. Sigstore and
Trusted Publishing are strong controls, but neither compensates for executing
unpinned workflow code.

Consider enabling Dependabot for `github-actions` so pinned SHAs are updated
through reviewed pull requests rather than going stale.

> **Node 20 deprecation notice in your run logs:** a warning, not a failure.
> `actions/checkout@v4.2.2` and `actions/setup-python@v5.3.0` target Node 20 and
> GitHub is currently forcing them onto Node 24. They still work.
>
> The fix is to move to `checkout@v5` and `setup-python@v6`, pinned to their
> commit SHAs. **Do not hand-write the SHAs** — a wrong one is a supply-chain
> problem, not a typo. Let Dependabot raise it as a reviewed pull request:
>
> ```yaml
> # .github/dependabot.yml
> version: 2
> updates:
>   - package-ecosystem: "github-actions"
>     directory: "/"
>     schedule: { interval: "weekly" }
> ```
>
> The same file also handles the `ubuntu-latest` → Ubuntu 26 migration notice.

> **If the run fails with `... are not allowed in <repo> because all actions
> must be pinned to a full-length commit SHA`:** that policy applies to
> **nested references**, not just yours. A third-party composite action that
> calls `actions/upload-artifact@v4` internally fails the check even when your
> reference to it is SHA-pinned — and you cannot fix a reference inside someone
> else's action.
>
> Both offenders are already gone from these workflows:
>
> | Was | Now | Why |
> |---|---|---|
> | `sigstore/gh-action-sigstore-python` | `python -m sigstore sign` | identical bundles, same ambient OIDC credential |
> | `softprops/action-gh-release` | `gh release create` | `gh` is preinstalled on the runner |
>
> `pypa/gh-action-pypi-publish` is the only third-party action left, and it
> stays — it *is* the Trusted Publishing path.
>
> If you still see this error, GitHub is running an older commit. Check
> `BUILD_ID`, re-extract and push.

## 4. Configure PyPI Trusted Publishing — before the first tag

This is the step people miss. The workflow publishes over OIDC and holds no API
token, so **PyPI must be told to trust your workflow before it will accept an
upload.**

**Check what already exists first.** These package names were published at
`0.6.0` during earlier development, so which flow you need depends on whether
*your account* owns them:

```bash
for p in attribution-graph paytrace handle-correlation attribution-suite; do
  echo "== $p"; pip index versions "$p" 2>&1 | head -2
done
```

Then, for each package, one of three situations:

**(a) The project exists and you own it.** Use the normal publisher flow, not a
pending one: <https://pypi.org/manage/project/PACKAGE/settings/publishing/>

**(b) The project does not exist.** Register a **pending publisher** at
<https://pypi.org/manage/account/publishing/>. PyPI creates the project on
first upload.

**(c) The project exists and you do NOT own it.** You cannot publish under that
name. Rename the package in `pyproject.toml` (and its dependants' pins) or use
a scoped name. Do this before tagging — a name collision surfaces as a
permission error at upload, after the gate has already passed.

Either flow takes the same four values:

| Field | Value |
|---|---|
| Owner | your GitHub handle |
| Repository name | same as the package name |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

Then create the environment in each GitHub repo:

**Settings → Environments → New environment → `pypi`**

The name must match exactly in both places. A mismatch surfaces at publish time
as a generic authorization failure naming no field.

**On republishing over 0.6.0:** PyPI will not let you re-upload an existing
version, but 2.0.0 is new, so this is an ordinary version bump. If the 0.6.0
artifacts were development builds you no longer want installed, `yank` them
after 2.0.0 is up — yanking keeps existing pins working while removing the
version from new resolutions.

## 5. Dry run on a pre-release version

Do this in **one** repository first — `attribution-graph`, since everything
depends on it.

The release gate requires the tag to match `pyproject.toml` **exactly**, so you
cannot rehearse by tagging `v2.0.0-rc1` against a `2.0.0` package: the gate
rejects it before publishing, which tests the guard rather than the release
path. Bump the version instead.

Note the PEP 440 form: `2.0.0rc1`, **no hyphen**. `2.0.0-rc1` is not a valid
version string and the wheel filename would not match.

```bash
cd attribution-graph
sed -i 's/^version = "2.0.0"/version = "2.0.0rc1"/' pyproject.toml
sed -i 's/^__version__ = "2.0.0"/__version__ = "2.0.0rc1"/' src/attribution_graph/__init__.py
git commit -am "rehearsal: 2.0.0rc1"
git tag v2.0.0rc1 && git push origin main v2.0.0rc1
```

Watch the run in the Actions tab and confirm four things:

1. **The `gate` job passes** — lint, bandit, tests, tag/version match, LICENSE
   check, build, `twine check`, clean-venv install.
2. **The `release` job downloads rather than rebuilds.** Its first step is
   *Download the gated distributions*. There must be no checkout and no
   `python -m build`. This is the invariant that makes the published artifact
   the same one that passed the gate.
3. **The hashes match.** The gate prints `SHA256SUMS`; compare against what
   PyPI shows for the uploaded files.
4. **The runtime closure was audited.** The gate installs the built wheel into
   a clean environment, freezes it as `runtime-requirements.txt` and audits
   *that*. An earlier version froze the gate environment — editable sources
   plus ruff, bandit, pytest, build and twine — and labelled it the released
   closure, which is the wrong artifact under a reassuring name.

5. **The dependency audit ran.** The gate runs `pip-audit --strict` against the
   closure it is about to publish and attaches `resolved-requirements.txt` to
   the release, so the set that shipped is recorded rather than inferred.

A pre-release does not become the default install — `pip install
attribution-graph` still resolves to the newest stable — so this is safe to
leave in place.

### Restore the version — do not skip this

**The rehearsal is not finished until this is done and pushed.** Leaving
`2.0.0rc1` in `pyproject.toml` is what makes the real tag fail later, with

```
::error::tag 2.0.0 does not match packaged version 2.0.0rc1
```

and by then the tag exists, so fixing it means moving a tag rather than editing
a file. `PUSH.sh` now refuses to run while a pre-release version is in place,
but restore it here and you will never see that.

```bash
sed -i 's/^version = "2.0.0rc1"/version = "2.0.0"/' pyproject.toml
sed -i 's/^__version__ = "2.0.0rc1"/__version__ = "2.0.0"/' src/attribution_graph/__init__.py
git commit -am "restore 2.0.0"
git push origin main

grep -m1 '^version' pyproject.toml     # must print 2.0.0 before you tag
```

> **Already hit `tag 2.0.0 does not match packaged version 2.0.0rc1`?**
> The tag exists and points at the rc commit. Restore the version, push, then
> move the tag onto the restored commit:
>
> ```bash
> sed -i 's/^version = "2.0.0rc1"/version = "2.0.0"/' pyproject.toml
> sed -i 's/^__version__ = "2.0.0rc1"/__version__ = "2.0.0"/' src/*/__init__.py
> git commit -am "restore 2.0.0 after rc1 rehearsal"
> git push origin main
>
> git tag -d v2.0.0
> git push origin :refs/tags/v2.0.0
> git tag v2.0.0
> git push origin v2.0.0
> ```

> **If you get `fatal: tag 'v2.0.0' already exists`:** you tagged during an
> earlier attempt, so the tag points at that older commit. Releasing it would
> ship code from before your later fixes, and git will not warn you. Check
> first:
>
> ```bash
> git log -1 --format='tag  -> %h %ci %s' v2.0.0
> git log -1 --format='HEAD -> %h %ci %s' HEAD
> git ls-remote --tags origin v2.0.0     # already pushed?
> pip index versions attribution-graph   # already on PyPI?
> ```
>
> **If 2.0.0 is NOT on PyPI** — move the tag to your current commit:
>
> ```bash
> git tag -d v2.0.0
> git push origin :refs/tags/v2.0.0      # only if it was already pushed
> git tag v2.0.0
> git push origin v2.0.0
> ```
>
> **If 2.0.0 IS on PyPI** — stop. PyPI permanently reserves a version, so it
> cannot be re-uploaded even after deletion. Bump instead, in all four:
>
> ```bash
> sed -i 's/^version = "2.0.0"/version = "2.0.1"/' pyproject.toml
> sed -i 's/^__version__ = "2.0.0"/__version__ = "2.0.1"/' src/*/__init__.py
> git commit -am "2.0.1" && git tag v2.0.1 && git push origin main v2.0.1
> ```


## 6. Real release — dependency order matters

`paytrace`, `handle-correlation` and `attribution-suite` all declare
`attribution-graph>=2.0.0`. If you tag them first, their release-gate
clean-venv install will fail: the dependency is not on PyPI yet.

Publish in this order, **waiting for each to appear on PyPI** before the next:

```bash
cd attribution-graph  && git tag v2.0.0 && git push origin v2.0.0
# wait for https://pypi.org/project/attribution-graph/2.0.0/

cd ../paytrace            && git tag v2.0.0 && git push origin v2.0.0
cd ../handle-correlation  && git tag v2.0.0 && git push origin v2.0.0
# these two are independent of each other

cd ../attribution-suite   && git tag v2.0.0 && git push origin v2.0.0
# last: it depends on all three
```

PyPI is usually available within a minute, but indexes can lag. If a gate fails
on a missing dependency, wait and re-run the job rather than changing anything.

## 7. Confirm the published result

```bash
python3 -m venv /tmp/check
/tmp/check/bin/pip install attribution-suite    # pulls all four from PyPI
cd /tmp && /tmp/check/bin/attribution version
```

All four must report `2.0.0`. Then check that the metadata is right:

```bash
/tmp/check/bin/pip show -f attribution-graph | grep -i home-page
```

It should point at your repository, not the placeholder.

## 8. Optional: a citable DOI

Connect Zenodo to GitHub (<https://zenodo.org/account/settings/github/>), enable
it for `attribution-graph`, then publish a **GitHub Release** from the `v2.0.0`
tag. Zenodo mints a DOI on release publication, not on the tag itself.

Add the DOI to `CITATION.cff` and push. That is what makes the work citable in a
paper.

---

## If something goes wrong

**The placeholder gate is red.** Step 1 was incomplete — `github.com/OWNER/`
still exists somewhere. The gate greps `pyproject.toml`, `README.md` and
`CITATION.cff`.

**Trusted Publishing rejects the upload.** The environment name in the GitHub
repo and in the PyPI publisher must match exactly (`pypi`), and the workflow
filename must be `release.yml`. The error message is unhelpfully generic.

**The release gate fails on a missing dependency.** You tagged out of order.
Wait for the dependency to appear on PyPI and re-run the job.

**You published something broken.** `yank` it rather than deleting it. Deleting
removes the files from anyone who tries to reinstall, and **does not** free the
version number — PyPI permanently reserves it, so you cannot re-upload a fixed
build under the same version either way. Yanking keeps existing pins resolvable
while removing the version from new resolutions, which is what you want.

**A version number is already taken.** PyPI does not allow re-uploading a
version, even after deletion. Bump to `2.0.1` and go again.

---

## After publishing

Two things the audit flagged that are yours, not the toolkit's:

- **The hosted release path is only exercised by a real tag.** Step 5 is that
  exercise. Do not skip it because CI is green — CI does not run the publish job.
- **This is an experimental/beta release.** The scoring model is not calibrated.
  Say so where people will see it: the repository description, the README badge,
  and any talk or paper. `METHODOLOGY_AUDIT.md` is the long form and is worth
  linking rather than summarising.
