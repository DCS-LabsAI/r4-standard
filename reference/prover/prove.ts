// SPDX-License-Identifier: MIT
//
// R+4 reference prover (TypeScript / snarkjs)
//
// Generates a Groth16 proof for the r4-threshold-count-v1 circuit.
// Input: R+3 audit bundle JSON + a statement JSON.
// Output: a canonical R+4 proof object per spec §7.
//
// Spec: https://dcslabs.ai/standard/r4
//
// Usage:
//   r4-prove --circuit r4-threshold-count-v1 \
//            --bundle ./q1-2026-bundle.json \
//            --statement ./statement.json \
//            --out ./proof.json

import { groth16, zKey } from "snarkjs";
import { readFile, writeFile } from "fs/promises";
import { canonicalize } from "json-canonicalize";  // RFC 8785

interface R3Bundle {
  bundle_root: string;
  receipts: Array<{
    hash: string;
    ts: string;
    policy_id: string;
    amount_usd_cents: number;
    nonce: string;
    signature: { R: [string, string]; S: string };
    merkle_path: { path: string[]; indices: number[] };
  }>;
  issuer_pk: [string, string];
  issuer_id: string;
}

interface R4Statement {
  circuit_id: "r4-threshold-count-v1";
  bundle_root: string;
  period_start: string;        // RFC 3339
  period_end: string;
  threshold: number;
  policy_id: string;
  amount_cap_usd_cents: number;
  issuer_id: string;
  issuer_pk?: [string, string];   // bound from the bundle at proving time
}

interface R4ProofObject {
  r4_version: "0.1.0";
  profile: "groth16-bn254";
  circuit_id: string;
  vk_hash: string;
  statement: R4Statement;
  proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[] };
  public_inputs: string[];
  issued_at: string;
  issuer_signature?: string;
  anchor?: { chain: string; tx_hash: string; block_number: number };
}

/**
 * Build witness inputs for the threshold-count circuit from an R+3 bundle.
 *
 * Filters the bundle to receipts that satisfy the statement (time window,
 * policy, amount cap), pads the rest with zero/inactive entries, and
 * encodes Merkle proofs + signatures for circom consumption.
 */
function buildWitness(
  bundle: R3Bundle,
  statement: R4Statement,
  MAX_RECEIPTS = 64,
  TREE_DEPTH = 20
) {
  const periodStart = Math.floor(Date.parse(statement.period_start) / 1000);
  const periodEnd = Math.floor(Date.parse(statement.period_end) / 1000);

  // Filter eligible receipts
  const eligible = bundle.receipts.filter((r) => {
    const ts = Math.floor(Date.parse(r.ts) / 1000);
    return (
      ts >= periodStart &&
      ts <= periodEnd &&
      r.policy_id === statement.policy_id &&
      r.amount_usd_cents <= statement.amount_cap_usd_cents
    );
  });

  if (eligible.length < statement.threshold) {
    throw new Error(
      `Eligible receipts (${eligible.length}) below threshold (${statement.threshold}). Cannot prove.`
    );
  }
  if (eligible.length > MAX_RECEIPTS) {
    throw new Error(
      `Eligible receipts (${eligible.length}) exceed MAX_RECEIPTS (${MAX_RECEIPTS}). Use recursive profile.`
    );
  }

  const padded = [...eligible];
  while (padded.length < MAX_RECEIPTS) {
    padded.push(zeroReceipt(TREE_DEPTH));
  }
  const isActive = padded.map((_, i) => (i < eligible.length ? 1 : 0));

  return {
    bundle_root: bundle.bundle_root,
    period_start: periodStart,
    period_end: periodEnd,
    threshold: statement.threshold,
    policy_id: hashToField(statement.policy_id),
    amount_cap: statement.amount_cap_usd_cents,
    issuer_pk: bundle.issuer_pk,
    active_count: eligible.length,
    is_active: isActive,
    receipt_hash: padded.map((r) => r.hash),
    receipt_ts: padded.map((r) => Math.floor(Date.parse(r.ts) / 1000)),
    receipt_policy_id: padded.map((r) => hashToField(r.policy_id)),
    receipt_amount: padded.map((r) => r.amount_usd_cents),
    receipt_nonce: padded.map((r) => r.nonce),
    merkle_path: padded.map((r) => r.merkle_path.path),
    merkle_indices: padded.map((r) => r.merkle_path.indices),
    sig_R: padded.map((r) => r.signature.R),
    sig_S: padded.map((r) => r.signature.S),
  };
}

function zeroReceipt(treeDepth: number) {
  return {
    hash: "0",
    ts: "1970-01-01T00:00:00Z",
    policy_id: "0",   // numeric — circom signals must be field elements, not ""
    amount_usd_cents: 0,
    nonce: "0",
    signature: { R: ["0", "0"] as [string, string], S: "0" },
    merkle_path: {
      path: Array(treeDepth).fill("0"),
      indices: Array(treeDepth).fill(0),
    },
  };
}

function hashToField(s: string): string {
  // Poseidon-friendly hash of the policy string into a field element.
  // (Full impl uses circomlibjs Poseidon; this is a sketch.)
  return s;
}

/**
 * Main proving entrypoint.
 */
export async function proveR4(
  circuitArtifactsDir: string,
  bundle: R3Bundle,
  statement: R4Statement
): Promise<R4ProofObject> {
  const wasmPath = `${circuitArtifactsDir}/threshold_count.wasm`;
  const zkeyPath = `${circuitArtifactsDir}/threshold_count_final.zkey`;
  const vkPath = `${circuitArtifactsDir}/verification_key.json`;

  const witnessInputs = buildWitness(bundle, statement);

  const { proof, publicSignals } = await groth16.fullProve(
    witnessInputs,
    wasmPath,
    zkeyPath
  );

  const vk = JSON.parse(await readFile(vkPath, "utf-8"));
  const vkHash = await sha256(JSON.stringify(vk));

  const proofObject: R4ProofObject = {
    r4_version: "0.1.0",
    profile: "groth16-bn254",
    circuit_id: "r4-threshold-count-v1",
    vk_hash: `sha256:${vkHash}`,
    // Embed issuer_pk (from the bundle) into the statement so the proof
    // is self-describing — the verifier can derive all 8 public inputs,
    // issuer_pk included, without a separate DID-resolution step.
    statement: { ...statement, issuer_pk: bundle.issuer_pk },
    proof: {
      pi_a: proof.pi_a,
      pi_b: proof.pi_b,
      pi_c: proof.pi_c,
    },
    public_inputs: publicSignals,
    issued_at: new Date().toISOString(),
  };

  // Canonicalize per RFC 8785 before any downstream signing
  const canonical = canonicalize(proofObject);
  // Optional: attach ed25519 issuer signature here

  return proofObject;
}

async function sha256(s: string): Promise<string> {
  const buf = new TextEncoder().encode(s);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// CLI entry
if (require.main === module) {
  (async () => {
    const args = process.argv.slice(2);
    // Return the value after --<k>, or undefined if the flag is absent.
    // (indexOf returns -1 when absent; args[-1 + 1] === args[0] would
    // otherwise silently mis-resolve a missing flag to the first argument —
    // which made --artifacts default to "--bundle".)
    const get = (k: string): string | undefined => {
      const i = args.indexOf(`--${k}`);
      return i === -1 ? undefined : args[i + 1];
    };
    const bundlePath = get("bundle");
    const statementPath = get("statement");
    const outPath = get("out") ?? "./proof.json";
    const artifactsDir = get("artifacts") ?? "./artifacts";

    if (!bundlePath || !statementPath) {
      console.error(
        "usage: r4-prove --bundle <bundle.json> --statement <statement.json>" +
          " [--out <proof.json>] [--artifacts <dir>]",
      );
      process.exit(2);
    }

    const bundle: R3Bundle = JSON.parse(await readFile(bundlePath, "utf-8"));
    const statement: R4Statement = JSON.parse(
      await readFile(statementPath, "utf-8")
    );

    const proof = await proveR4(artifactsDir, bundle, statement);
    await writeFile(outPath, canonicalize(proof));
    console.log(`✓ R+4 proof written to ${outPath}`);
    console.log(`  circuit:    ${proof.circuit_id}`);
    console.log(`  vk_hash:    ${proof.vk_hash}`);
    console.log(`  proof size: ${JSON.stringify(proof.proof).length} bytes`);
  })().catch((e) => {
    console.error("proving failed:", e);
    process.exit(1);
  });
}
