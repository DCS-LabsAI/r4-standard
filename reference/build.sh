#!/usr/bin/env bash
# ============================================================================
# R+4 build pipeline — compile the circuit and produce proving/verifying keys.
#
# Spec: https://dcslabs.ai/standard/r4  §5 Circuit Construction · §6 Setup
#
# This script takes the circuit from source to a working Groth16 key pair.
# It runs in two modes:
#
#   ./build.sh dev      — single-contributor setup. Fast (~2 min). Produces
#                         keys good for testing and the reference verifier.
#                         NOT trustless — one party knows the toxic waste.
#
#   ./build.sh prod     — expects ceremony/ to already hold the final .ptau
#                         from the multi-party ceremony (see ceremony/CEREMONY.md).
#                         Produces the production keys. Trustless as long as
#                         one ceremony contributor was honest.
#
# Prerequisites (install once on the build machine):
#   - circom 2.x       cargo install circom        (needs Rust)
#   - snarkjs          npm install -g snarkjs
#   - circomlib        npm install circomlib        (in this directory)
#
# Outputs land in  artifacts/:
#   threshold_count.r1cs              — the rank-1 constraint system
#   threshold_count_js/...            — the wasm witness generator
#   threshold_count_final.zkey        — the proving key
#   verification_key.json             — the verifying key (public)
# ============================================================================
set -euo pipefail

MODE="${1:-dev}"
CIRCUIT="circuits/threshold-count.circom"
OUT="artifacts"
mkdir -p "$OUT" ceremony

echo "── R+4 build · mode=$MODE ───────────────────────────────────────────"

# ── 1. compile the circuit ──────────────────────────────────────────────
echo "[1/5] compiling $CIRCUIT with circom …"
circom "$CIRCUIT" --r1cs --wasm --sym -o "$OUT" -l node_modules
echo "      → $OUT/threshold-count.r1cs"

# circom names outputs after the .circom file ("threshold-count", hyphen) and
# nests the wasm in a "<name>_js/" directory. The prover (prover/prove.ts)
# expects a flat underscore path "threshold_count.wasm" — normalise it here so
# the artifacts dir is self-consistent.
cp "$OUT/threshold-count_js/threshold-count.wasm" "$OUT/threshold_count.wasm"
echo "      → $OUT/threshold_count.wasm (flattened for the prover)"

# constraint count — sanity check it matches the spec cost model (§5.3)
snarkjs r1cs info "$OUT/threshold-count.r1cs"

# ── 2. Phase 1 — universal Powers of Tau ────────────────────────────────
# Phase 1 is circuit-independent. For dev we generate a fresh small ptau;
# for prod we reuse the published Perpetual Powers of Tau (do NOT regenerate).
PTAU="$OUT/pot22_final.ptau"
if [ "$MODE" = "prod" ]; then
  if [ ! -f ceremony/pot22_final.ptau ]; then
    echo "ERROR: prod mode needs ceremony/pot22_final.ptau (Perpetual Powers of Tau)."
    echo "       Download the appropriate power from the Ethereum PoT ceremony."
    exit 1
  fi
  cp ceremony/pot22_final.ptau "$PTAU"
  echo "[2/5] Phase 1 — using published Perpetual Powers of Tau"
else
  # The threshold-count circuit (64-receipt profile) compiles to ~1.2M R1CS
  # constraints, so Groth16 setup needs a Powers-of-Tau of power 22
  # (2^22 ≈ 4.2M ≥ 2·constraints). Generating a power-22 ptau locally is slow
  # and RAM-heavy, so prefer a prebuilt phase2-ready ptau dropped at
  # ceremony/pot22_final.ptau (see COMPILE_RUNBOOK §2). Generate only if absent.
  if [ -f ceremony/pot22_final.ptau ]; then
    echo "[2/5] Phase 1 — using prebuilt ceremony/pot22_final.ptau (power 22)"
    cp ceremony/pot22_final.ptau "$PTAU"
  else
    echo "[2/5] Phase 1 — generating a dev ptau (power 22 — slow, several minutes) …"
    snarkjs powersoftau new bn128 22 "$OUT/pot_0.ptau" -v
    snarkjs powersoftau contribute "$OUT/pot_0.ptau" "$OUT/pot_1.ptau" \
      --name="dev-contributor" -v -e="$(head -c 64 /dev/urandom | xxd -p | tr -d '\n')"
    snarkjs powersoftau prepare phase2 "$OUT/pot_1.ptau" "$PTAU" -v
  fi
fi

# ── 3. Phase 2 — circuit-specific setup ─────────────────────────────────
echo "[3/5] Phase 2 — Groth16 setup for threshold-count …"
snarkjs groth16 setup "$OUT/threshold-count.r1cs" "$PTAU" "$OUT/threshold_count_0.zkey"

if [ "$MODE" = "prod" ]; then
  if [ ! -f ceremony/phase2_final.zkey ]; then
    echo "ERROR: prod mode needs ceremony/phase2_final.zkey from the multi-party"
    echo "       Phase 2 ceremony. See ceremony/CEREMONY.md."
    exit 1
  fi
  cp ceremony/phase2_final.zkey "$OUT/threshold_count_final.zkey"
  echo "      → using ceremony Phase 2 output (multi-party, trustless)"
else
  # dev: a single contribution then finalise
  snarkjs zkey contribute "$OUT/threshold_count_0.zkey" "$OUT/threshold_count_1.zkey" \
    --name="dev-contributor" -v -e="$(head -c 64 /dev/urandom | xxd -p | tr -d '\n')"
  snarkjs zkey beacon "$OUT/threshold_count_1.zkey" "$OUT/threshold_count_final.zkey" \
    0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 \
    --name="dev-beacon"
  echo "      → dev proving key (single-contributor — NOT for production trust)"
fi

# ── 4. export the verifying key ─────────────────────────────────────────
echo "[4/5] exporting verification_key.json …"
snarkjs zkey export verificationkey "$OUT/threshold_count_final.zkey" "$OUT/verification_key.json"

# ── 5. export the on-chain Solidity verifier ────────────────────────────
echo "[5/5] exporting Solidity verifier → solidity/Groth16Verifier.gen.sol …"
snarkjs zkey export solidityverifier "$OUT/threshold_count_final.zkey" \
  solidity/Groth16Verifier.gen.sol

echo
echo "── R+4 build complete ──────────────────────────────────────────────"
echo "  proving key : $OUT/threshold_count_final.zkey"
echo "  verify key  : $OUT/verification_key.json"
echo "  wasm        : $OUT/threshold-count_js/threshold-count.wasm"
echo "  solidity    : solidity/Groth16Verifier.gen.sol"
echo
echo "  next:  npm run prove -- --bundle example-bundle.json \\"
echo "                          --statement example-statement.json --out proof.json"
echo "         npm run verify -- proof.json"
if [ "$MODE" = "dev" ]; then
  echo
  echo "  NOTE: these are DEV keys. For production, run the multi-party"
  echo "        ceremony (ceremony/CEREMONY.md) then: ./build.sh prod"
fi
