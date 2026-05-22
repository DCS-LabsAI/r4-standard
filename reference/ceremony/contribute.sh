#!/usr/bin/env bash
# ============================================================================
# R+4 Phase 2 ceremony — contributor script.
#
# Run this on an AIR-GAPPED, freshly-installed machine. After it finishes,
# send back the output .zkey and the printed contribution hash, then WIPE
# this machine. Your secret entropy must not survive.
#
# Spec: https://dcslabs.ai/standard/r4 §6 · see ceremony/CEREMONY.md
#
# Usage:  ./contribute.sh <previous.zkey> <your-name>
# ============================================================================
set -euo pipefail

PREV="${1:?usage: ./contribute.sh <previous.zkey> <your-name>}"
NAME="${2:?usage: ./contribute.sh <previous.zkey> <your-name>}"
OUT="phase2_${NAME}.zkey"

if [ ! -f "$PREV" ]; then
  echo "ERROR: previous zkey '$PREV' not found."
  exit 1
fi

echo "── R+4 Phase 2 contribution ────────────────────────────────────────"
echo "  contributor : $NAME"
echo "  input       : $PREV"
echo "  output      : $OUT"
echo

# Fresh entropy. Combine a kernel CSPRNG draw with live operator keyboard
# entropy — snarkjs also mixes its own. The -e value never touches disk.
echo "  Type ~100 random characters then press Enter (adds keyboard entropy):"
read -r KEYBOARD_ENTROPY
ENTROPY="$(head -c 64 /dev/urandom | xxd -p | tr -d '\n')${KEYBOARD_ENTROPY}$(date +%s%N)"

snarkjs zkey contribute "$PREV" "$OUT" --name="$NAME" -v -e="$ENTROPY"

# wipe the entropy variable from this shell
ENTROPY=""
KEYBOARD_ENTROPY=""

echo
echo "── contribution complete ───────────────────────────────────────────"
echo "  Send back:  $OUT"
echo
echo "  Your contribution hash was printed by 'snarkjs zkey contribute'"
echo "  just above (the 'Contribution Hash:' block). Copy that 12-line"
echo "  hash — it IS your attestation. Publish it so the coordinator and"
echo "  the public can confirm your .zkey is the one you actually made."
echo
echo "  To reprint it, the coordinator can run:  snarkjs zkey verify \\"
echo "    threshold-count.r1cs pot_final.ptau $OUT"
echo
echo "  THEN: wipe this machine. Your secret randomness must not survive."
echo "        The whole ceremony's security depends on it."
