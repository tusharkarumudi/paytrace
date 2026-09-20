#!/usr/bin/env bash
#
# Full verification. Run before every push, release, or hand-off.
#
#   ./VERIFY.sh            # everything
#   ./VERIFY.sh --fast     # skip build and clean-room install
#
# Run from the directory containing the four repos. Exits non-zero on any
# failure, so it is safe to gate CI or a release script on it.

set -uo pipefail

REPOS=(attribution-graph paytrace handle-correlation attribution-suite)
FAST=0
[ "${1:-}" = "--fast" ] && FAST=1

FAILED=0
pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; FAILED=1; }
head() { printf '\n\033[1m%s\033[0m\n' "$1"; }

run() {  # run <label> <command...>
  local label="$1"; shift
  if "$@" >/tmp/verify.log 2>&1; then pass "$label"; else
    fail "$label"; sed 's/^/      /' /tmp/verify.log | tail -15; fi
}

for r in "${REPOS[@]}"; do
  [ -d "$r" ] || { echo "error: $r not found — run from the repos directory" >&2; exit 2; }
done

# --------------------------------------------------------------------------- #
# Bootstrap. The documented flow is unpack -> VERIFY.sh -> PUSH.sh, and PUSH.sh
# is what runs `git init`. Assuming installed packages and initialised repos
# made a clean archive fail for environmental reasons rather than for defects,
# which is the worst kind of red: it trains people to ignore the gate.
head "0. Bootstrap"

MISSING_TOOLS=""
for t in python3 pip; do command -v "$t" >/dev/null || MISSING_TOOLS="$MISSING_TOOLS $t"; done
[ -z "$MISSING_TOOLS" ] || { echo "error: missing:$MISSING_TOOLS" >&2; exit 2; }

# Hermetic by default: a disposable venv, so verification never mutates the
# caller's environment. VERIFY_IN_PLACE=1 opts out for a developer who wants
# the editable installs to persist.
if [ "${VERIFY_IN_PLACE:-0}" = "1" ]; then
  echo "   VERIFY_IN_PLACE=1 — installing into the current environment"
  for r in "${REPOS[@]}"; do
    ( cd "$r" && python3 -m pip install -q -e . 2>/dev/null ) \
      || ( cd "$r" && python3 -m pip install -q -e . --break-system-packages )
  done
  for t in ruff bandit pytest pytest-asyncio; do
    command -v "$t" >/dev/null || python3 -m pip install -q "$t" 2>/dev/null \
      || python3 -m pip install -q "$t" --break-system-packages || true
  done
  pass "installed in place"
else
  VENV="${VERIFY_VENV:-$PWD/.verify-venv}"
  if [ ! -x "$VENV/bin/python" ]; then
    echo "   creating $VENV"
    python3 -m venv "$VENV" || { echo "error: venv creation failed" >&2; exit 2; }
  fi
  "$VENV/bin/pip" install -q -U pip >/dev/null 2>&1 || true
  for r in "${REPOS[@]}"; do
    ( cd "$r" && "$VENV/bin/pip" install -q -e . ) \
      || { echo "error: installing $r failed" >&2; exit 2; }
  done
  "$VENV/bin/pip" install -q ruff bandit pytest pytest-asyncio build twine \
    || { echo "error: tooling install failed" >&2; exit 2; }
  # Everything downstream runs from the venv.
  PATH="$VENV/bin:$PATH"
  export PATH
  pass "hermetic environment at $VENV"
fi

python3 -c "import attribution_graph, paytrace, handle_correlation, attribution_suite" \
  || { echo "error: packages not importable after bootstrap" >&2; exit 2; }
pass "packages importable"

# Stages 8 and 9 read git metadata. A fresh archive has none, so initialise a
# local repo rather than skipping the artifact-hygiene checks entirely -- those
# are exactly the checks a first-time pusher needs most.
for r in "${REPOS[@]}"; do
  if [ ! -d "$r/.git" ]; then
    ( cd "$r" && git init -q -b main && git add -A ) 2>/dev/null \
      && echo "   initialised git in $r for hygiene checks"
  fi
done

# --------------------------------------------------------------------------- #
head "0. Clean bytecode"
# Stale .pyc files silently shadow corrected source. During a self-audit this
# made three already-fixed functions test as regressions, and cost more time
# than any real defect in this pass. Always start from source.
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
pass "bytecode cleared"

head "1. Static analysis"
for r in "${REPOS[@]}"; do
  ( cd "$r" && ruff check . ) >/tmp/verify.log 2>&1 \
    && pass "ruff       $r" || { fail "ruff       $r"; tail -8 /tmp/verify.log | sed 's/^/      /'; }
done
for r in "${REPOS[@]}"; do
  ( cd "$r" && bandit -r src -ll -q ) >/tmp/verify.log 2>&1 \
    && pass "bandit     $r" || { fail "bandit     $r"; tail -8 /tmp/verify.log | sed 's/^/      /'; }
done

# --------------------------------------------------------------------------- #
head "2. Unit tests"
TOTAL=0
for r in "${REPOS[@]}"; do
  # Exit status decides. Parsing the last line of output classified a pytest
  # killed with 137 as PASS, because its final line happened to be ".". A gate
  # that can report success for a process that died is worse than no gate.
  if ( cd "$r" && python -m pytest tests -q ) >/tmp/verify.log 2>&1; then
    out=$( tail -1 /tmp/verify.log )
    n=$( echo "$out" | grep -oE '^[0-9]+' || echo 0 )
    TOTAL=$((TOTAL + n))
    pass "$(printf '%-22s %s' "$r" "$out")"
  else
    rc=$?
    fail "$r — pytest exited $rc"
    tail -15 /tmp/verify.log | sed 's/^/      /'
  fi
done
echo "     $TOTAL tests total"

# --------------------------------------------------------------------------- #
head "3. Integration tests (cross-package)"
# Four packages that depend on each other fail at the seams, not inside them.
if ( cd attribution-suite && python -m pytest tests/test_integration.py -q ) \
     >/tmp/verify.log 2>&1; then
  pass "integration            $( tail -1 /tmp/verify.log )"
else
  rc=$?
  fail "integration — pytest exited $rc"
  tail -15 /tmp/verify.log | sed 's/^/      /'
fi

head "4. Adversarial subset (injection, obfuscation, SSRF)"
for r in "${REPOS[@]}"; do
  # pytest exits 5 when no test matched the -k filter, which is not a failure
  # here: not every package carries adversarial tests.
  ( cd "$r" && python -m pytest tests -q \
      -k "obfuscation or injection or security or adversarial or guard" ) \
      >/tmp/verify.log 2>&1
  rc=$?
  case "$rc" in
    0) pass "$(printf '%-22s %s' "$r" "$( tail -1 /tmp/verify.log )")" ;;
    5) pass "$(printf '%-22s (no adversarial tests)' "$r")" ;;
    *) fail "$r — pytest exited $rc"
       tail -15 /tmp/verify.log | sed 's/^/      /' ;;
  esac
done

# --------------------------------------------------------------------------- #
head "5. Version alignment"
python3 - <<'PY' && pass "all four report one version" || fail "versions diverge"
import importlib, sys
v = {m: importlib.import_module(m).__version__ for m in
     ("attribution_graph", "paytrace", "handle_correlation", "attribution_suite")}
print(v)
sys.exit(0 if len(set(v.values())) == 1 else 1)
PY

# --------------------------------------------------------------------------- #
head "6. Examples run offline"
( cd paytrace && python examples/end_to_end_domain.py >/dev/null 2>&1 \
  && python examples/reference_collector.py >/dev/null 2>&1 && rm -rf out-demo ) \
  && pass "paytrace examples" || fail "paytrace examples"
( cd handle-correlation && python examples/end_to_end_handles.py >/dev/null 2>&1 ) \
  && pass "handle-correlation example" || fail "handle-correlation example"
( cd attribution-graph && python examples/worked_example.py >/dev/null 2>&1 \
  && rm -rf out case.demo.yaml ) \
  && pass "attribution-graph example" || fail "attribution-graph example"

head "7. Injection demo (talk-critical)"
( cd paytrace && timeout 60 python demo/run_demo.py >/dev/null 2>&1 ) \
  && pass "four-act demo completes" || fail "four-act demo"
( cd paytrace && python - <<'PY' >/dev/null 2>&1
from paytrace.agent import Agent, Toolbox, FixtureFetcher, FixtureIndex
naive = Agent(Toolbox(FixtureFetcher(poisoned=True), FixtureIndex()),
              guards_enabled=False).run("attribute scraper-site.example")
armed = Agent(Toolbox(FixtureFetcher(poisoned=True), FixtureIndex()),
              guards_enabled=True).run("attribute scraper-site.example")
assert naive.conclusion == "Northwind Hosting Cooperative"
assert armed.conclusion == "Example Media Holdings Ltd"
PY
) && pass "demo outcome is deterministic" || fail "demo outcome drifted"

# --------------------------------------------------------------------------- #
head "8. Artifact hygiene"
# Investigation artifacts in git history are permanent, in every clone and fork.
for r in "${REPOS[@]}"; do
  bad=$( cd "$r" && git ls-files 2>/dev/null | grep -iE \
    "(^|/)(evidence|captures)/|^audit.*\.jsonl$|^case\.yaml$|\.sqlite$|^\.env$|^\.pypirc$" \
    | grep -v "^tests/" || true )
  [ -z "$bad" ] && pass "no artifacts tracked  $r" || fail "$r tracks: $bad"
done
for r in "${REPOS[@]}"; do
  miss=""
  for p in "out/" "evidence/" "case.yaml" "audit.jsonl" "x.sqlite" ".env"; do
    ( cd "$r" && git check-ignore -q "$p" ) || miss="$miss $p"
  done
  [ -z "$miss" ] && pass "gitignore covers    $r" || fail "$r misses:$miss"
done

head "9. Secrets and internal references"
grep -rInE "(api[_-]?key|token|secret|password)[[:space:]]*[:=][[:space:]]*['\"][A-Za-z0-9_-]{16,}" \
  --include="*.py" --include="*.yml" --include="*.toml" . 2>/dev/null \
  | grep -v "os.environ\|example\|EXAMPLE\|placeholder" > /tmp/verify.log
[ ! -s /tmp/verify.log ] && pass "no hardcoded credentials" \
  || { fail "possible credentials"; sed 's/^/      /' /tmp/verify.log | head -5; }

grep -rIn "meta\.com\|fb\.com\|CONFIDENTIAL\|internal-only" \
  --include="*.py" --include="*.md" . 2>/dev/null \
  | grep -v "example\|placeholder" > /tmp/verify.log
[ ! -s /tmp/verify.log ] && pass "no internal references" \
  || { fail "internal references"; sed 's/^/      /' /tmp/verify.log | head -5; }

# The 796-domain infrastructure blacklist is operational data, not method.
( cd attribution-graph && python -c "
from attribution_graph.filters import SHARED_INFRA_DOMAINS
assert not SHARED_INFRA_DOMAINS, 'blacklist must ship empty'" ) \
  && pass "infra blacklist ships empty" || fail "infra blacklist not empty"

head "10. Ownership and licensing"
for r in "${REPOS[@]}"; do
  ok=1
  [ -f "$r/NOTICE" ] || ok=0
  [ -f "$r/CITATION.cff" ] || ok=0
  grep -q "Tushar Karumudi" "$r/pyproject.toml" || ok=0
  [ "$ok" = 1 ] && pass "ownership metadata  $r" || fail "ownership metadata  $r"
done
STUBS=$(grep -l "PLACEHOLDER" ./*/LICENSE 2>/dev/null | wc -l)
[ "$STUBS" = "0" ] && pass "LICENSE files are real" \
  || fail "$STUBS LICENSE file(s) still stubbed — replace before pushing"

# --------------------------------------------------------------------------- #
if [ "$FAST" = "0" ]; then
  head "11. Build"
  for r in "${REPOS[@]}"; do
    ( cd "$r" && rm -rf dist && python -m build -q && twine check dist/* ) \
      >/tmp/verify.log 2>&1 && pass "wheel + sdist       $r" \
      || { fail "build              $r"; tail -12 /tmp/verify.log | sed 's/^/      /'; }
  done

  # Package data must actually ship: the registry catalog fails at runtime for
  # every user if it does not, and passes every local test.
  python3 - <<'PY' && pass "package data in wheel" || fail "package data missing"
import glob, zipfile, sys
w = glob.glob("paytrace/dist/*.whl")
if not w:
    sys.exit(1)
sys.exit(0 if any("data/registries.yaml" in n
                  for n in zipfile.ZipFile(w[0]).namelist()) else 1)
PY

  for r in "${REPOS[@]}"; do
    hits=$( tar tzf "$r"/dist/*.tar.gz 2>/dev/null | grep -iE \
      "(^|/)(evidence|captures)/|audit.*\.jsonl|\.sqlite$|/case\.yaml$|\.env$" || true )
    [ -z "$hits" ] && pass "sdist clean         $r" || fail "$r sdist leaks: $hits"
  done

  head "12. Clean-room install from wheels"
  rm -rf /tmp/verify-venv && python3 -m venv /tmp/verify-venv
  V=/tmp/verify-venv/bin
  FL=""
  for r in "${REPOS[@]}"; do FL="$FL --find-links $PWD/$r/dist"; done
  INSTALL_OK=1
  for r in "${REPOS[@]}"; do
    $V/pip install -q $FL "$PWD/$r"/dist/*.whl >/tmp/verify.log 2>&1 || INSTALL_OK=0
  done
  [ "$INSTALL_OK" = 1 ] && pass "installs from wheels" || fail "wheel install"

  # cd out of the source tree, or imports resolve to src/ and prove nothing.
  ( cd /tmp && $V/python - <<'PY'
import importlib, sys
for m in ("attribution_graph", "paytrace", "handle_correlation", "attribution_suite"):
    mod = importlib.import_module(m)
    assert "/verify-venv/" in mod.__file__, f"{m} resolved from the source tree"

from paytrace import load_catalog
from paytrace.collectors import registry
from paytrace.netsec import safe_host
from attribution_graph.scoring import Band, band_for
from attribution_suite import ask, Refused

assert len(load_catalog()) >= 30
assert len(registry()) >= 34
assert safe_host("169.254.169.254") is None
assert band_for(1.0, 1) is Band.WEAK
r = ask("who operates scraper-site.example?", offline=True)
assert r.conclusion == "Example Media Holdings Ltd"
try:
    ask("Who Is Jane Doe?", offline=True); sys.exit(1)
except Refused:
    pass
PY
  ) && pass "clean-room smoke" || fail "clean-room smoke"

  for c in paytrace paytrace-index handlecorr attribution; do
    [ -x "$V/$c" ] && pass "console script      $c" || fail "console script      $c"
  done
  rm -rf /tmp/verify-venv
fi

# --------------------------------------------------------------------------- #
head "Result"
if [ "$FAILED" = "0" ]; then
  printf '  \033[32mALL CHECKS PASSED\033[0m — %s unit tests plus integration\n\n' "$TOTAL"
  exit 0
else
  printf '  \033[31mFAILURES ABOVE — do not release\033[0m\n\n'
  exit 1
fi
