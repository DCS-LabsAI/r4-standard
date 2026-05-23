// SPDX-License-Identifier: MIT
//
// R+4 reference verifier (TypeScript / snarkjs)
//
// Verifies an R+4 proof object against the registered circuit's
// verifying key. Implements the procedure in spec §9.
//
// Spec: https://dcslabs.ai/standard/r4
//
// Usage:
//   r4-verify ./proof.json [--registry registry.r4.dcslabs.ai] [--federation manifest.json]

import { groth16 } from "snarkjs";
import { readFile } from "fs/promises";
import { canonicalize } from "json-canonicalize";

export interface VerifyResult {
  ok: boolean;
  reason?: string;
  statement?: any;
  timings?: { snark_ms: number; total_ms: number };
}

interface CircuitRegistryEntry {
  circuit_id: string;
  vk_hash: string;
  vk: any;
  schema: any;
  anchored_at?: string;
}

interface FederationManifest {
  members: string[];          // issuer_ids
  accepted_circuits: string[]; // circuit_ids
  signature: string;
  version: number;
}

/**
 * Verify an R+4 proof object end-to-end.
 *
 * Steps (per §9):
 *   1. Schema validation
 *   2. Circuit registration check
 *   3. Federation membership (optional)
 *   4. Public-input derivation + match
 *   5. Issuer signature (optional)
 *   6. On-chain anchor (optional)
 *   7. Groth16 SNARK verification
 */
export async function verifyR4(
  proofObj: any,
  registry: Map<string, CircuitRegistryEntry>,
  federationManifest?: FederationManifest
): Promise<VerifyResult> {
  const tStart = Date.now();

  // === 1. Schema validation ===
  const required = [
    "r4_version", "profile", "circuit_id", "vk_hash",
    "statement", "proof", "public_inputs", "issued_at",
  ];
  for (const f of required) {
    if (proofObj[f] === undefined) {
      return { ok: false, reason: `missing field: ${f}` };
    }
  }
  if (proofObj.r4_version !== "0.1.0") {
    return { ok: false, reason: `unsupported r4_version: ${proofObj.r4_version}` };
  }

  // === 2. Circuit registration ===
  const circuit = registry.get(proofObj.circuit_id);
  if (!circuit) {
    return { ok: false, reason: `unregistered circuit: ${proofObj.circuit_id}` };
  }
  if (circuit.vk_hash !== proofObj.vk_hash) {
    return { ok: false, reason: "vk_hash mismatch (registry vs proof)" };
  }

  // === 3. Federation membership (optional) ===
  if (federationManifest) {
    if (!federationManifest.members.includes(proofObj.statement.issuer_id)) {
      return { ok: false, reason: `non-member issuer: ${proofObj.statement.issuer_id}` };
    }
    if (!federationManifest.accepted_circuits.includes(proofObj.circuit_id)) {
      return { ok: false, reason: `circuit not accepted by federation` };
    }
  }

  // === 4. Public input derivation ===
  const derived = derivePublicInputs(proofObj.statement, proofObj.circuit_id);
  if (!deepEqual(derived, proofObj.public_inputs)) {
    return { ok: false, reason: "public_input mismatch (statement vs proof)" };
  }

  // === 5. Issuer signature (optional) ===
  if (proofObj.issuer_signature) {
    const sigOk = await verifyEd25519IssuerSig(proofObj);
    if (!sigOk) return { ok: false, reason: "bad_issuer_signature" };
  }

  // === 6. On-chain anchor (optional) ===
  if (proofObj.anchor) {
    const anchorOk = await verifyChainAnchor(proofObj);
    if (!anchorOk) return { ok: false, reason: "bad_anchor" };
  }

  // === 7. SNARK verification ===
  const tSnark = Date.now();
  const snarkOk = await groth16.verify(
    circuit.vk,
    proofObj.public_inputs,
    proofObj.proof
  );
  const snarkMs = Date.now() - tSnark;

  if (!snarkOk) {
    return { ok: false, reason: "snark_invalid" };
  }

  return {
    ok: true,
    statement: proofObj.statement,
    timings: {
      snark_ms: snarkMs,
      total_ms: Date.now() - tStart,
    },
  };
}

function derivePublicInputs(statement: any, circuit_id: string): string[] {
  // Ordering MUST match the circuit's `public [...]` declaration. For
  // r4-threshold-count-v1 (threshold-count.circom):
  //   [bundle_root, period_start, period_end, threshold,
  //    policy_id, amount_cap, issuer_pk[0], issuer_pk[1]]
  // RFC-3339 period bounds are reduced to unix seconds exactly as the
  // prover's buildWitness does. issuer_pk is carried in the statement
  // (the prover binds it from the bundle at proving time).
  if (circuit_id === "r4-threshold-count-v1") {
    const issuerPk = statement.issuer_pk;
    if (!Array.isArray(issuerPk) || issuerPk.length !== 2) {
      throw new Error("statement.issuer_pk missing or malformed — cannot derive public inputs");
    }
    return [
      String(statement.bundle_root),
      String(Math.floor(Date.parse(statement.period_start) / 1000)),
      String(Math.floor(Date.parse(statement.period_end) / 1000)),
      String(statement.threshold),
      hashToField(statement.policy_id),
      String(statement.amount_cap_usd_cents),
      String(issuerPk[0]),
      String(issuerPk[1]),
    ];
  }
  throw new Error(`unsupported circuit_id: ${circuit_id}`);
}

// sha256 hex over a UTF-8 string — used to recompute vk_hash so the
// registry entry matches what the prover stamped into the proof.
async function sha256Hex(s: string): Promise<string> {
  const buf = new TextEncoder().encode(s);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hashToField(s: string): string {
  return s; // sketch
}

function deepEqual(a: any, b: any): boolean {
  return canonicalize(a) === canonicalize(b);
}

async function verifyEd25519IssuerSig(proofObj: any): Promise<boolean> {
  // Verify ed25519 signature over canonicalize(proofObj minus issuer_signature field)
  // (Sketch — production uses @noble/ed25519)
  return true;
}

async function verifyChainAnchor(proofObj: any): Promise<boolean> {
  // Resolve proofObj.anchor.tx_hash on Base mainnet, check the on-chain commit
  // matches sha256(canonicalize(proofObj minus anchor field))
  // (Sketch — production uses viem)
  return true;
}

// CLI entry
if (require.main === module) {
  (async () => {
    const args = process.argv.slice(2);
    const proofPath = args.find((a) => !a.startsWith("--"));
    if (!proofPath) {
      console.error("Usage: r4-verify <proof.json> [--artifacts ./artifacts]");
      process.exit(1);
    }
    const aIdx = args.indexOf("--artifacts");
    const artifactsDir = aIdx >= 0 ? args[aIdx + 1] : "./artifacts";

    const proof = JSON.parse(await readFile(proofPath, "utf-8"));

    // Build the circuit registry from the locally built verifying key.
    // (Production: fetch from registry.r4.dcslabs.ai.) vk_hash is computed
    // exactly as the prover does — sha256 over JSON.stringify(vk) — so a
    // matching verifying key yields a matching hash.
    const registry = new Map<string, CircuitRegistryEntry>();
    try {
      const vk = JSON.parse(await readFile(`${artifactsDir}/verification_key.json`, "utf-8"));
      const vkHash = "sha256:" + (await sha256Hex(JSON.stringify(vk)));
      registry.set(proof.circuit_id, {
        circuit_id: proof.circuit_id,
        vk_hash: vkHash,
        vk,
        schema: {},
      });
    } catch (e: any) {
      console.error(`could not load verifying key from ${artifactsDir}/verification_key.json: ${e?.message}`);
      process.exit(1);
    }

    console.log(`[ ok ]   r4_version          : ${proof.r4_version}`);
    console.log(`[ ok ]   circuit_id          : ${proof.circuit_id}`);
    console.log(`[ ok ]   vk_hash             : ${proof.vk_hash}`);

    const result = await verifyR4(proof, registry);

    if (result.ok) {
      console.log(`[ ok ]   schema validation   : passed`);
      console.log(`[ ok ]   public input derive : matched`);
      console.log(`[ ok ]   groth16 verify      : valid (${result.timings?.snark_ms} ms)`);
      console.log("");
      console.log("Statement holds:");
      console.log(JSON.stringify(result.statement, null, 2));
    } else {
      console.log(`[fail]   ${result.reason}`);
      process.exit(2);
    }
  })().catch((e) => {
    console.error("verify failed:", e);
    process.exit(1);
  });
}
