#!/usr/bin/env bash
#
# Push the four packages to GitHub. Does not publish to PyPI -- that happens
# when you tag, through the release workflow.
#
#   GH_OWNER=yourhandle GIT_EMAIL=you@example.org ./PUSH.sh
#   GH_OWNER=yourhandle GIT_EMAIL=you@example.org DRY_RUN=1 ./PUSH.sh
#
# Idempotent: safe to re-run. Existing repos get a new commit, not a clobber.

set -euo pipefail

GH_OWNER="${GH_OWNER:-}"
GIT_EMAIL="${GIT_EMAIL:-}"
GIT_NAME="${GIT_NAME:-Tushar Karumudi}"
DRY_RUN="${DRY_RUN:-0}"
VISIBILITY="${VISIBILITY:-public}"
#: https (default, via the gh credential helper) or ssh.
GIT_PROTOCOL="${GIT_PROTOCOL:-https}"

REPOS=(attribution-graph paytrace handle-correlation attribution-suite)

die() { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$1"; }
run() { if [ "$DRY_RUN" = "1" ]; then printf '   would run: %s\n' "$*"; else "$@"; fi; }

[ -n "$GH_OWNER" ]  || die "set GH_OWNER=yourhandle"
[ -n "$GIT_EMAIL" ] || die "set GIT_EMAIL=you@example.org (used for commit authorship)"
command -v git >/dev/null || die "git not found"
command -v gh  >/dev/null || die "GitHub CLI not found: https://cli.github.com"
gh auth status >/dev/null 2>&1 || die "run: gh auth login"

# GitHub disabled account passwords for Git operations in August 2021, but the
# HTTPS prompt still ASKS for one and then rejects it -- so a correct password
# produces "Authentication failed", which reads like the password is wrong.
#
# `gh` being logged in is not enough on its own: git needs to be told to use
# gh's credentials. This is that step, and it is idempotent.
if ! git config --get-all credential.helper 2>/dev/null | grep -q "gh auth"; then
  say "Connecting git to your gh credentials"
  gh auth setup-git || die "gh auth setup-git failed.

Alternatives:
  - SSH:   gh auth refresh -h github.com -s admin:public_key
           then re-run with GIT_PROTOCOL=ssh
  - Token: create a classic PAT with 'repo' scope at
           https://github.com/settings/tokens and use it as the PASSWORD
           at the prompt (your account password will never work)."
  echo "   git will now use gh for github.com"
fi

# Every repo here ships .github/workflows/. Pushing workflow files over an
# OAuth token requires the `workflow` scope, and without it the push is
# rejected AFTER the commit is made and the repo is created -- a confusing
# half-done state. Check before touching anything.
if ! gh auth status 2>&1 | grep -qE "'workflow'|\bworkflow\b"; then
  say "Requesting the 'workflow' token scope"
  echo "   These repositories contain .github/workflows/, and GitHub rejects"
  echo "   pushes that create or update workflow files without this scope."
  gh auth refresh -h github.com -s workflow || die "could not add the 'workflow' scope.

Run this yourself and then re-run PUSH.sh:

    gh auth refresh -h github.com -s workflow

If you use a Personal Access Token instead of gh's OAuth login, the token
needs BOTH the 'repo' and 'workflow' scopes:
    https://github.com/settings/tokens"
  echo "   scope granted"
fi

for r in "${REPOS[@]}"; do
  [ -d "$r" ] || die "$r not found — run this from the directory holding the four packages"
done

# --------------------------------------------------------------------------- #
say "Pre-flight"

# The release gate refuses a placeholder LICENSE and placeholder URLs, so catch
# both here rather than after four pushes.
for r in "${REPOS[@]}"; do
  grep -q PLACEHOLDER "$r/LICENSE" && die "$r/LICENSE is still a placeholder"
  if grep -rq "github.com/OWNER/" "$r/pyproject.toml" "$r/README.md" 2>/dev/null; then
    die "$r still contains the OWNER placeholder in its metadata"
  fi
done
echo "   LICENSE and project URLs are real"

# Metadata must point at the owner you are actually pushing to, or PyPI
# Trusted Publishing will not match the repository it was configured for.
for r in "${REPOS[@]}"; do
  if ! grep -q "github.com/$GH_OWNER/" "$r/pyproject.toml"; then
    die "$r/pyproject.toml does not reference github.com/$GH_OWNER — update Project-URLs before pushing, or Trusted Publishing will not match"
  fi
done
echo "   project URLs match GH_OWNER=$GH_OWNER"

# Show which build is on disk. Repeated CI failures against a step that does
# not exist in your source mean GitHub has an older commit than you think, and
# nothing in a git status makes that obvious.
if [ -f attribution-graph/BUILD_ID ]; then
  echo "   archive build: $(grep -m1 '^build:' attribution-graph/BUILD_ID | cut -d' ' -f2)"
fi

VERSION=$(grep -m1 '^version' attribution-graph/pyproject.toml | cut -d'"' -f2)

# A pre-release version left in place after a rehearsal is the trap: the gate
# requires the tag to equal the packaged version exactly, so tagging v2.0.0
# against a 2.0.0rc1 package fails AFTER the tag exists -- and fixing it then
# means moving a tag rather than editing a file.
case "$VERSION" in
  *rc*|*a[0-9]*|*b[0-9]*|*dev*)
    die "pyproject.toml still declares a PRE-RELEASE version: $VERSION

This is what is left behind after a rehearsal. Restore the real version in all
four packages before tagging:

    for r in ${REPOS[*]}; do
      sed -i 's/^version = \"$VERSION\"/version = \"${VERSION%%rc*}\"/' \$r/pyproject.toml
      sed -i 's/^__version__ = \"$VERSION\"/__version__ = \"${VERSION%%rc*}\"/' \$r/src/*/__init__.py
    done

Then commit, push, and only then tag. If v${VERSION%%rc*} already exists, move
it onto the restored commit -- see PUBLISHING.md."
    ;;
esac
for r in "${REPOS[@]}"; do
  v=$(grep -m1 '^version' "$r/pyproject.toml" | cut -d'"' -f2)
  [ "$v" = "$VERSION" ] || die "version mismatch: attribution-graph=$VERSION $r=$v"
done
echo "   all four at $VERSION"

# A missing gate is a hard stop. "Skipping" silently converted the pre-push
# release gate into a no-op for anyone whose archive did not happen to include
# VERIFY.sh at the root -- which was every archive.
if [ -f ./VERIFY.sh ] && [ ! -x ./VERIFY.sh ]; then
  # Archive formats lose the executable bit routinely -- zip stores modes but
  # many extractors drop them, and some transports normalise to 0600. Restore
  # it rather than failing on a permission bit the operator never set.
  echo "   VERIFY.sh is present but not executable; restoring the mode"
  chmod +x ./VERIFY.sh 2>/dev/null || true
fi

if [ ! -x ./VERIFY.sh ]; then
  die "VERIFY.sh not found or not executable in $(pwd).

It ships inside each package; copy one to the root of your workspace:
    cp attribution-graph/VERIFY.sh . && chmod +x VERIFY.sh

Pushing without it means the release gate never ran. If you have a considered
reason to proceed anyway, set SKIP_VERIFY=1 explicitly -- but the tagged
release workflow runs the same checks and will fail later at greater cost."
fi

if [ "${SKIP_VERIFY:-0}" = "1" ]; then
  echo "   SKIP_VERIFY=1 — the release gate did NOT run" >&2
else
  say "Running VERIFY.sh (this is the gate; do not push past it)"
  ./VERIFY.sh || die "VERIFY.sh failed — fix before pushing"
fi

# --------------------------------------------------------------------------- #
say "Pushing"

for r in "${REPOS[@]}"; do
  echo
  echo "-- $r"
  (
    cd "$r"

    if [ ! -d .git ]; then
      run git init -q -b main
    fi

    # Applied unconditionally. VERIFY.sh initialises .git for its artifact
    # hygiene checks, so gating identity on "did I create the repo" meant the
    # GIT_EMAIL and GIT_NAME the operator supplied were silently ignored --
    # failing outright on a machine with no global identity, and worse,
    # committing under the wrong one on a machine that has it.
    run git config user.email "$GIT_EMAIL"
    run git config user.name  "$GIT_NAME"

    # Refuse to commit investigation artifacts even if .gitignore is wrong.
    if git ls-files --others --exclude-standard 2>/dev/null \
         | grep -qE '(^|/)(evidence|captures)/|audit.*\.jsonl$|\.sqlite$|^\.env$'; then
      die "$r has untracked investigation artifacts — clean them before pushing"
    fi

    run git add -A
    if [ "$DRY_RUN" != "1" ] && [ -d .git ]; then
      changed=$(git diff --cached --name-only | grep -c . || true)
      wf=$(git diff --cached --name-only | grep -c '^\.github/workflows/' || true)
      echo "   staged: $changed file(s), $wf workflow file(s)"
    fi
    if [ "$DRY_RUN" = "1" ]; then
      printf '   would commit: %s v%s\n' "$r" "$VERSION"
    elif git diff --cached --quiet; then
      echo "   nothing to commit"
    else
      git commit -q -m "$r v$VERSION

Entity attribution toolchain. Experimental/beta: the scoring model is
evidence-strength ranked and not calibrated. See METHODOLOGY_AUDIT.md."
    fi

    if ! gh repo view "$GH_OWNER/$r" >/dev/null 2>&1; then
      echo "   creating $GH_OWNER/$r ($VISIBILITY)"
      run gh repo create "$GH_OWNER/$r" "--$VISIBILITY" \
          --description "$(grep -m1 '^description' pyproject.toml | cut -d'"' -f2)" \
          --source . --remote origin
      # gh picks the remote protocol from its own git_protocol config, which
      # can differ per repo and produced a mixed https/ssh set. Normalise.
      if [ "$GIT_PROTOCOL" = "ssh" ]; then
        run git remote set-url origin "git@github.com:$GH_OWNER/$r.git"
      else
        run git remote set-url origin "https://github.com/$GH_OWNER/$r.git"
      fi
    else
      if [ "$GIT_PROTOCOL" = "ssh" ]; then
        remote_url="git@github.com:$GH_OWNER/$r.git"
      else
        remote_url="https://github.com/$GH_OWNER/$r.git"
      fi
      if git remote get-url origin >/dev/null 2>&1; then
        run git remote set-url origin "$remote_url"
      else
        run git remote add origin "$remote_url"
      fi
    fi

    # A tag left from an earlier attempt points at that older commit, so
    # releasing it ships code from before the work just staged. Nothing in git
    # warns about this -- the release simply publishes the wrong tree.
    if [ -d .git ]; then
      for t in $(git tag -l 'v*' 2>/dev/null); do
        tc=$(git rev-parse "$t^{commit}" 2>/dev/null) || continue
        if [ "$tc" != "$(git rev-parse HEAD)" ] && \
           git merge-base --is-ancestor "$tc" HEAD 2>/dev/null; then
          echo "   WARNING: tag $t points behind HEAD"
          echo "            $t -> $(git rev-parse --short "$tc"), HEAD -> $(git rev-parse --short HEAD)"
          echo "            Move it before releasing:  git tag -d $t && git tag $t"
        fi
      done
    fi

    if [ "$DRY_RUN" = "1" ]; then
      printf '   would push: %s\n' "$r"
    elif ! git push -u origin main 2>/tmp/push.err; then
      cat /tmp/push.err >&2
      if grep -qE "fetch first|non-fast-forward|rejected.*main" /tmp/push.err; then
        die "push failed for $r: the remote already has commits you do not have.

This repository name exists on GitHub with different content -- most often an
earlier release of this same package. Nothing has been lost; inspect it first:

    cd $r
    git fetch origin
    git log --oneline origin/main | head -20

If the file names look like THIS project at an earlier version, that is the
usual case, and rebasing is the wrong tool: two unrelated histories of the same
files conflict add/add on every single file, and resolving them by hand gains
nothing because v2.0.0 supersedes the lot.

  Preserve the old history on a branch, then replace main:

    git fetch origin main
    git branch pre-2.0.0 FETCH_HEAD
    git push origin pre-2.0.0
    git push --force-with-lease origin main

    --force-with-lease, not --force: it refuses if someone pushed since your
    fetch, so you cannot clobber a change you have not seen. The branch keeps
    the old commits reachable, so this stays reversible.

  Only if the remote holds genuinely DIFFERENT work you want merged:

    git pull --rebase --allow-unrelated-histories origin main
    # then resolve conflicts, or: git rebase --abort

Then re-run PUSH.sh to finish the remaining repositories."
      fi
      if grep -q "workflow.*scope" /tmp/push.err; then
        die "push failed for $r: the token lacks the 'workflow' scope.

These repositories ship .github/workflows/, which GitHub protects. Fix with:

    gh auth refresh -h github.com -s workflow

then re-run this script. Nothing is lost -- the commit is already made and
PUSH.sh is idempotent, so it will resume from here.

Using a PAT instead? It needs BOTH 'repo' and 'workflow' scopes."
      fi
      die "push failed for $r.

If you were prompted for a password: GitHub stopped accepting account
passwords for Git in August 2021. The prompt still appears, so a correct
password still fails.

  gh auth setup-git          # use your gh login for git (recommended)
  GIT_PROTOCOL=ssh ./PUSH.sh # or push over SSH instead

If you use a Personal Access Token, it goes in the PASSWORD field, not the
username, and needs the 'repo' scope."
    fi
  )
done

# --------------------------------------------------------------------------- #
echo
say "Pushed. Do NOT tag yet."
cat <<NEXT

Next, in order. PUBLISHING.md is the full procedure; this is the short form and
is kept in sync with it.

  1. Check what already exists on PyPI. These names were published at 0.6.0
     during earlier development, so the flow depends on who owns them now:

       for p in ${REPOS[*]}; do
         echo "== \$p"; pip index versions "\$p" 2>&1 | head -2
       done

     - exists and you own it -> normal publisher flow, per project:
         https://pypi.org/manage/project/PACKAGE/settings/publishing/
     - does not exist        -> PENDING publisher:
         https://pypi.org/manage/account/publishing/
     - exists, someone else owns it -> you cannot publish under that name.
         Rename in pyproject.toml and in the dependants' pins BEFORE tagging.

     Either flow takes the same four values:
       Owner:        $GH_OWNER
       Repository:   <the package name>
       Workflow:     release.yml
       Environment:  pypi

  2. Create the 'pypi' environment in each GitHub repo
     (Settings -> Environments -> New environment -> "pypi").
     The name must match exactly in both places.

  3. Rehearse with a real pre-release, in attribution-graph only.

     The gate requires the tag to equal pyproject.toml EXACTLY, so a
     v${VERSION}-rc1 tag against a ${VERSION} package is rejected before
     publishing -- that tests the guard, not the release path. Bump instead.
     Note the PEP 440 form: ${VERSION}rc1, no hyphen.

       cd attribution-graph
       sed -i 's/^version = "${VERSION}"/version = "${VERSION}rc1"/' pyproject.toml
       sed -i 's/^__version__ = "${VERSION}"/__version__ = "${VERSION}rc1"/' \
         src/attribution_graph/__init__.py
       git commit -am "rehearsal: ${VERSION}rc1"
       git tag v${VERSION}rc1 && git push origin main v${VERSION}rc1

     Confirm: the gate passes; the release job's FIRST step is
     "Download the gated distributions" with no checkout and no build;
     the published hashes match the SHA256SUMS the gate printed.

     Then restore ${VERSION} and push before step 4.

  4. Real release, in dependency order. The other three pin
     attribution-graph>=${VERSION}, so it must be on PyPI first. Wait for each
     to appear before tagging the next:

       attribution-graph
       paytrace, handle-correlation   (independent of each other)
       attribution-suite              (depends on all three)
NEXT
