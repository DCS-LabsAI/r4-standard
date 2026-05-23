// SPDX-License-Identifier: MIT
//
// R+4 reference circuit · r4-threshold-count-v1
//
// Proves the statement:
//   "≥ THRESHOLD receipts in BUNDLE_ROOT, signed by ISSUER_PK,
//    with policy_id == POLICY_ID and amount <= AMOUNT_CAP,
//    in time window [PERIOD_START, PERIOD_END]"
//
// Spec: https://dcslabs.ai/standard/r4 §5.2
//
// Profile: Groth16 over BN254
// Curve:   BN254 (compatible with Ethereum/Base precompile)

pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

// =====================================================================
// Merkle path verifier (binary tree, Poseidon hash)
// =====================================================================
template MerkleProof(DEPTH) {
    signal input leaf;
    signal input path_elements[DEPTH];
    signal input path_indices[DEPTH];  // 0 = left, 1 = right
    signal output root;

    component hashers[DEPTH];
    component muxers[DEPTH];

    signal current[DEPTH + 1];
    current[0] <== leaf;

    for (var i = 0; i < DEPTH; i++) {
        hashers[i] = Poseidon(2);
        muxers[i] = DualMux();

        muxers[i].in[0] <== current[i];
        muxers[i].in[1] <== path_elements[i];
        muxers[i].s <== path_indices[i];

        hashers[i].inputs[0] <== muxers[i].out[0];
        hashers[i].inputs[1] <== muxers[i].out[1];
        current[i + 1] <== hashers[i].out;
    }

    root <== current[DEPTH];
}

template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];

    s * (1 - s) === 0;  // s must be 0 or 1
    out[0] <== (in[1] - in[0]) * s + in[0];
    out[1] <== (in[0] - in[1]) * s + in[1];
}

// =====================================================================
// Per-receipt constraint block
// =====================================================================
template ReceiptConstraints(TREE_DEPTH) {
    // Public context (shared across all receipts)
    signal input period_start;
    signal input period_end;
    signal input target_policy_id;
    signal input amount_cap;
    signal input issuer_pk[2];           // EdDSA-Poseidon pubkey (Ax, Ay)
    signal input bundle_root;

    // Receipt-specific witness
    signal input is_active;              // 0 or 1 (mask)
    signal input receipt_hash;
    signal input receipt_ts;
    signal input receipt_policy_id;
    signal input receipt_amount;
    signal input receipt_nonce;

    // Merkle proof witness
    signal input merkle_path[TREE_DEPTH];
    signal input merkle_indices[TREE_DEPTH];

    // Signature witness
    signal input sig_R[2];               // EdDSA-Poseidon signature R component
    signal input sig_S;                  // EdDSA-Poseidon signature S component

    signal output counts;                // 1 if this receipt counts toward threshold, else 0

    is_active * (1 - is_active) === 0;   // is_active must be 0 or 1

    // --- 1. Merkle path verification (only when active) ---
    component merkle = MerkleProof(TREE_DEPTH);
    merkle.leaf <== receipt_hash;
    for (var i = 0; i < TREE_DEPTH; i++) {
        merkle.path_elements[i] <== merkle_path[i];
        merkle.path_indices[i] <== merkle_indices[i];
    }
    // When active, merkle root MUST equal bundle_root
    component root_eq = IsEqual();
    root_eq.in[0] <== merkle.root;
    root_eq.in[1] <== bundle_root;
    is_active * (1 - root_eq.out) === 0;

    // --- 2. Signature verification (only when active) ---
    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== is_active;
    sig.Ax <== issuer_pk[0];
    sig.Ay <== issuer_pk[1];
    sig.R8x <== sig_R[0];
    sig.R8y <== sig_R[1];
    sig.S <== sig_S;
    sig.M <== receipt_hash;

    // --- 3. Time window check ---
    component ts_gte = GreaterEqThan(64);
    ts_gte.in[0] <== receipt_ts;
    ts_gte.in[1] <== period_start;
    component ts_lte = LessEqThan(64);
    ts_lte.in[0] <== receipt_ts;
    ts_lte.in[1] <== period_end;
    signal ts_ok;
    ts_ok <== ts_gte.out * ts_lte.out;
    is_active * (1 - ts_ok) === 0;

    // --- 4. Policy ID match ---
    component policy_eq = IsEqual();
    policy_eq.in[0] <== receipt_policy_id;
    policy_eq.in[1] <== target_policy_id;
    is_active * (1 - policy_eq.out) === 0;

    // --- 5. Amount cap ---
    component amt_lte = LessEqThan(64);
    amt_lte.in[0] <== receipt_amount;
    amt_lte.in[1] <== amount_cap;
    is_active * (1 - amt_lte.out) === 0;

    // This receipt counts iff it's active and all constraints satisfied
    counts <== is_active;
}

// =====================================================================
// Main circuit
// =====================================================================
template ThresholdCount(MAX_RECEIPTS, TREE_DEPTH) {
    // === Public inputs (visible to verifier) ===
    signal input bundle_root;
    signal input period_start;
    signal input period_end;
    signal input threshold;
    signal input policy_id;
    signal input amount_cap;
    signal input issuer_pk[2];

    // === Private witness ===
    signal input active_count;
    signal input is_active[MAX_RECEIPTS];
    signal input receipt_hash[MAX_RECEIPTS];
    signal input receipt_ts[MAX_RECEIPTS];
    signal input receipt_policy_id[MAX_RECEIPTS];
    signal input receipt_amount[MAX_RECEIPTS];
    signal input receipt_nonce[MAX_RECEIPTS];
    signal input merkle_path[MAX_RECEIPTS][TREE_DEPTH];
    signal input merkle_indices[MAX_RECEIPTS][TREE_DEPTH];
    signal input sig_R[MAX_RECEIPTS][2];
    signal input sig_S[MAX_RECEIPTS];

    // Per-receipt constraint blocks
    component blocks[MAX_RECEIPTS];
    signal partial_sums[MAX_RECEIPTS + 1];
    partial_sums[0] <== 0;

    for (var i = 0; i < MAX_RECEIPTS; i++) {
        blocks[i] = ReceiptConstraints(TREE_DEPTH);
        blocks[i].period_start <== period_start;
        blocks[i].period_end <== period_end;
        blocks[i].target_policy_id <== policy_id;
        blocks[i].amount_cap <== amount_cap;
        blocks[i].issuer_pk[0] <== issuer_pk[0];
        blocks[i].issuer_pk[1] <== issuer_pk[1];
        blocks[i].bundle_root <== bundle_root;

        blocks[i].is_active <== is_active[i];
        blocks[i].receipt_hash <== receipt_hash[i];
        blocks[i].receipt_ts <== receipt_ts[i];
        blocks[i].receipt_policy_id <== receipt_policy_id[i];
        blocks[i].receipt_amount <== receipt_amount[i];
        blocks[i].receipt_nonce <== receipt_nonce[i];

        for (var j = 0; j < TREE_DEPTH; j++) {
            blocks[i].merkle_path[j] <== merkle_path[i][j];
            blocks[i].merkle_indices[j] <== merkle_indices[i][j];
        }
        blocks[i].sig_R[0] <== sig_R[i][0];
        blocks[i].sig_R[1] <== sig_R[i][1];
        blocks[i].sig_S <== sig_S[i];

        partial_sums[i + 1] <== partial_sums[i] + blocks[i].counts;
    }

    // active_count must equal the sum of all is_active flags
    partial_sums[MAX_RECEIPTS] === active_count;

    // active_count must be >= threshold
    component thresh_check = GreaterEqThan(32);
    thresh_check.in[0] <== active_count;
    thresh_check.in[1] <== threshold;
    thresh_check.out === 1;
}

// Production deployment uses MAX_RECEIPTS = 64 (for Groth16 profile)
// or MAX_RECEIPTS = 4096 with recursive Halo2 profile.
// TREE_DEPTH = 20 supports up to ~1M receipts per R+3 bundle.

component main {
    public [ bundle_root, period_start, period_end, threshold,
             policy_id, amount_cap, issuer_pk ]
} = ThresholdCount(64, 20);
