#!/usr/bin/env bash
#
# reproduce.sh — best-effort off-chain reproducibility check for the
# DCS Labs R-Series.
#
# Scope: runs the OFF-CHAIN R+2 and R+3 reference checks and prints a
# pass/fail summary. It does NOT cover:
#   - R+4 (witness / proof adversarial / ceremony verify) — run manually,
#     see REPRODUCE.md sections 3.1-3.3.
#   - On-chain block-explorer verification — see REPRODUCE.md section 4.
#
# Honest notes:
#   - This is best-effort, not a guaranteed one-command reproduction.
#     Each repo needs its own `npm install`; this script runs it for you.
#   - The R+2 adversarial suite is EXPECTED to report 9 passed + 1
#     documented nonce-uniqueness gap. That outcome is treated as the
#     expected result, not a hard failure (see note in the summary).
#   - `npm install` needs network access. No other network is assumed.

set -u

# Resolve repo root: this script lives in <repo-root>/rseries-hardening/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

R2_DIR="$ROOT/r2-standard-repo/verifier"
R3_DIR="$ROOT/r3-standard/reference"

# --- result tracking -------------------------------------------------
declare -a RESULT_NAMES
declare -a RESULT_STATES   # PASS | FAIL | SKIP | NOTE

record() {
  RESULT_NAMES+=("$1")
  RESULT_STATES+=("$2")
}

hr() { printf '%s\n' "------------------------------------------------------------"; }

# Run a command in a given dir; record PASS/FAIL by exit code.
# Usage: run_step "<label>" "<dir>" <cmd> [args...]
run_step() {
  local label="$1"; shift
  local dir="$1"; shift
  hr
  echo ">> $label"
  echo "   dir: $dir"
  echo "   cmd: $*"
  hr
  if ( cd "$dir" && "$@" ); then
    echo "[ ok ] $label"
    record "$label" "PASS"
  else
    echo "[FAIL] $label"
    record "$label" "FAIL"
  fi
}

echo "============================================================"
echo " DCS Labs R-Series — off-chain reproducibility check"
echo " repo root: $ROOT"
echo "============================================================"

# --- prerequisite probe ---------------------------------------------
if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: 'node' not found on PATH. Install Node.js LTS (>=18) first."
  exit 1
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "ERROR: 'npm' not found on PATH. Install npm (ships with Node.js)."
  exit 1
fi
echo "node: $(node --version)   npm: $(npm --version)"

# ====================================================================
# R+2  —  r2-standard-repo/verifier/
# ====================================================================
echo
echo "### R+2 — Open Provenance Standard"
if [ -d "$R2_DIR" ]; then
  run_step "R+2 npm install" "$R2_DIR" npm install
  # Only run tests if install succeeded.
  if [ "${RESULT_STATES[${#RESULT_STATES[@]}-1]}" = "PASS" ]; then
    run_step "R+2 unit tests (npm test)"            "$R2_DIR" npm test
    run_step "R+2 conformance (10 vectors)"         "$R2_DIR" npm run conformance
    run_step "R+2 scale (10k receipts)"             "$R2_DIR" npm run scale

    # Adversarial: 9 passed + 1 documented nonce-uniqueness gap is EXPECTED.
    hr
    echo ">> R+2 adversarial suite (node test/adversarial.test.js)"
    echo "   NOTE: expected result is 9 passed + 1 documented"
    echo "   nonce-uniqueness gap. Review the printed output to"
    echo "   confirm the only non-pass is that documented gap."
    hr
    ( cd "$R2_DIR" && node test/adversarial.test.js )
    echo "[note] R+2 adversarial — see output above; expected 9 pass + 1 gap."
    record "R+2 adversarial (expect 9 pass + 1 documented gap)" "NOTE"
  else
    echo "[skip] R+2 tests skipped — npm install did not succeed."
    record "R+2 unit tests"   "SKIP"
    record "R+2 conformance"  "SKIP"
    record "R+2 scale"        "SKIP"
    record "R+2 adversarial"  "SKIP"
  fi
else
  echo "[skip] R+2 repo not found at: $R2_DIR"
  record "R+2 (repo present)" "SKIP"
fi

# ====================================================================
# R+3  —  r3-standard/reference/
# ====================================================================
echo
echo "### R+3 — Tamper-Evident Audit Export"
if [ -d "$R3_DIR" ]; then
  run_step "R+3 npm install" "$R3_DIR" npm install
  if [ "${RESULT_STATES[${#RESULT_STATES[@]}-1]}" = "PASS" ]; then
    run_step "R+3 regression (npm test, expect 10/10)" "$R3_DIR" npm test
    run_step "R+3 adversarial (expect 6/6)"            "$R3_DIR" npx tsx test/adversarial.test.ts
  else
    echo "[skip] R+3 tests skipped — npm install did not succeed."
    record "R+3 regression"  "SKIP"
    record "R+3 adversarial" "SKIP"
  fi
else
  echo "[skip] R+3 repo not found at: $R3_DIR"
  record "R+3 (repo present)" "SKIP"
fi

# ====================================================================
# Summary
# ====================================================================
echo
echo "============================================================"
echo " SUMMARY"
echo "============================================================"
fail_count=0
for i in "${!RESULT_NAMES[@]}"; do
  state="${RESULT_STATES[$i]}"
  printf ' [%-4s] %s\n' "$state" "${RESULT_NAMES[$i]}"
  if [ "$state" = "FAIL" ]; then
    fail_count=$((fail_count + 1))
  fi
done
echo "------------------------------------------------------------"
echo "NOT covered by this script (run manually — see REPRODUCE.md):"
echo "  - R+4 witness tests, proof adversarial suite, ceremony verify"
echo "  - All on-chain block-explorer verification"
echo "------------------------------------------------------------"

if [ "$fail_count" -eq 0 ]; then
  echo "RESULT: off-chain R+2 + R+3 checks completed with no hard failures."
  echo "        (Confirm the R+2 adversarial output shows 9 pass + 1 gap.)"
  exit 0
else
  echo "RESULT: $fail_count step(s) FAILED — review the output above."
  exit 1
fi
