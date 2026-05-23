// ===========================================================================
// R+4 "Federation Protocol" — cross-issuer proof verification
// R+4 spec §8.2 (Cross-Issuer Verification Algorithm)
// ===========================================================================
//
// SCOPE: single-process reference implementation (see manifest.ts header).
// This module decides whether a Groth16 proof produced by one federation
// member should be accepted by another, given a signed federation manifest.
// ===========================================================================

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { canonicalize } from "json-canonicalize";
import { verifyManifest, type FederationManifest } from "./manifest.js";

// snarkjs ships no first-class types; import is loosely typed.
import { groth16 } from "snarkjs";

// ── types ──────────────────────────────────────────────────────────────────

/**
 * An R+4 proof object as emitted by r4-prove. Shape mirrors example-proof.json
 * and proof.json in the reference repo.
 */
export interface R4ProofObject {
  circuit_id: string;
  vk_hash?: string;
  statement: {
    issuer_id: string;
    [k: string]: unknown;
  };
  proof: unknown;            // { pi_a, pi_b, pi_c } — Groth16 proof points
  public_inputs: string[];   // public signals
  [k: string]: unknown;
}

/** snarkjs verifying key object. */
export type VerifyingKey = Record<string, unknown>;

/**
 * Callback that resolves a circuit_id to its snarkjs verifying key. Injected
 * so the federation layer stays transport-agnostic — in a real deployment
 * this would fetch the vk from a member registry or content-addressed store.
 */
export type GetVerifyingKey = (
  circuitId: string,
) => VerifyingKey | null | undefined | Promise<VerifyingKey | null | undefined>;

export interface CrossIssuerResult {
  ok: boolean;
  /** Machine-readable failure stage, or "verified" on success. */
  reason: string;
}

// ── helpers ──────────────────────────────────────────────────────────────────

/** SHA-256 of a canonicalised verifying key, as "sha256:<64 hex>". */
export function vkHash(vk: VerifyingKey): string {
  return "sha256:" + bytesToHex(sha256(utf8ToBytes(canonicalize(vk))));
}

// ── §8.2 cross-issuer verification ──────────────────────────────────────────

/**
 * Verify a cross-issuer R+4 proof per R+4 spec §8.2.
 *
 * Steps (each a clean rejection on failure — never throws):
 *   1. the federation manifest signature is valid
 *   2. proofObject.statement.issuer_id is a manifest member
 *   3. proofObject.circuit_id is an accepted circuit
 *   4. the verifying key resolved for that circuit hashes to the
 *      manifest's registered vk_hash
 *   5. the Groth16 pairing check passes
 *
 * @param proofObject      the R+4 proof to check.
 * @param manifest         a SIGNED federation manifest.
 * @param getVerifyingKey  resolver for circuit verifying keys.
 * @param federationPubKey the federation authority's Ed25519 public key
 *                         (hex or bytes) used to validate the manifest.
 */
export async function verifyCrossIssuerProof(
  proofObject: R4ProofObject,
  manifest: FederationManifest,
  getVerifyingKey: GetVerifyingKey,
  federationPubKey: Uint8Array | string,
): Promise<CrossIssuerResult> {
  try {
    // ── step 1: manifest signature ──────────────────────────────────────
    const mv = verifyManifest(manifest, federationPubKey);
    if (!mv.ok) {
      return { ok: false, reason: "manifest_invalid: " + (mv.reason ?? "unknown") };
    }

    // basic proof-object shape check
    if (!proofObject || typeof proofObject !== "object") {
      return { ok: false, reason: "proof_malformed: not an object" };
    }
    if (!proofObject.statement || typeof proofObject.statement.issuer_id !== "string") {
      return { ok: false, reason: "proof_malformed: missing statement.issuer_id" };
    }
    if (typeof proofObject.circuit_id !== "string") {
      return { ok: false, reason: "proof_malformed: missing circuit_id" };
    }
    if (!Array.isArray(proofObject.public_inputs)) {
      return { ok: false, reason: "proof_malformed: missing public_inputs" };
    }

    // ── step 2: issuer is a federation member ───────────────────────────
    const member = manifest.members.find(
      (m) => m.issuer_id === proofObject.statement.issuer_id,
    );
    if (!member) {
      return {
        ok: false,
        reason: `issuer_not_member: ${proofObject.statement.issuer_id}`,
      };
    }

    // ── step 3: circuit is accepted by the federation ──────────────────
    const circuit = manifest.accepted_circuits.find(
      (c) => c.circuit_id === proofObject.circuit_id,
    );
    if (!circuit) {
      return {
        ok: false,
        reason: `circuit_not_accepted: ${proofObject.circuit_id}`,
      };
    }

    // ── step 4: verifying key resolves and matches the manifest hash ────
    const vk = await getVerifyingKey(proofObject.circuit_id);
    if (!vk || typeof vk !== "object") {
      return {
        ok: false,
        reason: `vk_unavailable: ${proofObject.circuit_id}`,
      };
    }
    const computed = vkHash(vk);
    if (computed !== circuit.vk_hash) {
      return {
        ok: false,
        reason: `vk_hash_mismatch: expected ${circuit.vk_hash}, got ${computed}`,
      };
    }
    // if the proof carries its own vk_hash, it must agree with the manifest.
    if (proofObject.vk_hash && proofObject.vk_hash !== circuit.vk_hash) {
      return {
        ok: false,
        reason: `vk_hash_mismatch: proof claims ${proofObject.vk_hash}`,
      };
    }

    // ── step 5: Groth16 pairing check ──────────────────────────────────
    let groth16Ok: boolean;
    try {
      groth16Ok = await groth16.verify(
        vk as any,
        proofObject.public_inputs,
        proofObject.proof as any,
      );
    } catch (e) {
      return {
        ok: false,
        reason: "groth16_error: " + (e instanceof Error ? e.message : String(e)),
      };
    }
    if (!groth16Ok) {
      return { ok: false, reason: "groth16_invalid: pairing check failed" };
    }

    return { ok: true, reason: "verified" };
  } catch (e) {
    // catch-all: §8.2 demands a clean rejection on every failure path.
    return {
      ok: false,
      reason: "exception: " + (e instanceof Error ? e.message : String(e)),
    };
  }
}
