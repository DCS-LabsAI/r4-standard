// ===========================================================================
// R+4 "Federation Protocol" — cross-issuer END-TO-END verification test
// R+4 spec §8.2 (Cross-Issuer Verification Algorithm) — all five steps live.
// ===========================================================================
//
// SCOPE / HONESTY NOTICE
// ----------------------
// This is the v0.2 end-to-end test for the SINGLE-PROCESS federation
// reference. Unlike federation.test.ts (which uses a STUB verifying key and
// can therefore only reach — not pass — the Groth16 stage), this suite wires
// in a REAL dev-key Groth16 verifying key and a REAL dev-key proof, both
// exported from the r4-reference circuit pipeline (federation/fixtures/).
//
// As a result §8.2 step 5 runs `groth16.verify` against genuine pairing
// inputs and returns TRUE for the authentic proof. The negative half mutates
// one public input and confirms the very same code path returns FALSE.
//
// The verifying key here is a DEVELOPMENT key. The production-ceremony vk
// would be exported from phase2_final.zkey separately; nothing about the
// §8.2 algorithm changes when that swap happens.
//
// Run: npx tsx federation/test/cross-issuer-e2e.test.ts
// ===========================================================================

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import * as ed from "@noble/ed25519";

import {
  buildManifest,
  signManifest,
  verifyManifest,
} from "../manifest.js";
import {
  verifyCrossIssuerProof,
  vkHash,
  type R4ProofObject,
  type VerifyingKey,
} from "../cross-issuer.js";

ed.hashes.sha512 = (...m) => sha512(ed.etc.concatBytes(...m));

let pass = 0;
let fail = 0;
function check(name: string, ok: boolean, detail?: string) {
  console.log(`  ${ok ? "[ ok ]" : "[FAIL]"}  ${name}${detail ? "  — " + detail : ""}`);
  ok ? pass++ : fail++;
}

console.log(
  "R+4 — cross-issuer END-TO-END test (real Groth16 verify, real dev-key vk)\n",
);

// Resolve fixture paths relative to this file (cwd-independent).
const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "fixtures");

async function main(): Promise<void> {

  // ── load the real artifacts ──────────────────────────────────────────────
  const realVk: VerifyingKey = JSON.parse(
    readFileSync(join(FIXTURES, "verification_key.json"), "utf8"),
  );
  const realProofFile = JSON.parse(
    readFileSync(join(FIXTURES, "proof.json"), "utf8"),
  );

  // The fixture proof.json carries a `vk_hash` field that was computed by an
  // earlier pipeline using a different hashing convention than this module's
  // RFC-8785 + SHA-256 vkHash(). To keep §8.2 step 4 honest we register the
  // manifest with the hash THIS module actually computes over the real vk,
  // and we do NOT rely on the proof's stale embedded hash. (Step 4 still
  // fully runs: it recomputes vkHash(vk) and compares it to the manifest.)
  const REAL_VK_HASH = vkHash(realVk);
  const CIRCUIT_ID: string = realProofFile.circuit_id;
  const PROOF_ISSUER: string = realProofFile.statement.issuer_id;

  // The R+4 proof object handed to the §8.2 verifier. We omit the stale
  // embedded vk_hash so step 4 compares manifest-hash against the freshly
  // computed vk hash only — the genuine cross-issuer check.
  const realProof: R4ProofObject = {
    circuit_id: CIRCUIT_ID,
    statement: realProofFile.statement,
    proof: realProofFile.proof,
    public_inputs: realProofFile.public_inputs,
  };

  // ── set up: federation authority + the proof's real issuer as a member ───
  const authoritySk = ed.utils.randomSecretKey();
  const authorityPk = bytesToHex(ed.getPublicKey(authoritySk));

  const memberSk = ed.utils.randomSecretKey();
  const memberPubkey = bytesToHex(ed.getPublicKey(memberSk));

  // Genesis manifest: 1 member (= the issuer that produced the real proof),
  // 1 accepted circuit whose vk_hash is the REAL verifying key's hash.
  const manifest = signManifest(
    buildManifest({
      federation_id: "fed:dcs:r4-reference",
      members: [{ issuer_id: PROOF_ISSUER, issuer_pubkey: memberPubkey }],
      accepted_circuits: [{ circuit_id: CIRCUIT_ID, vk_hash: REAL_VK_HASH }],
    }),
    authoritySk,
    "authority-key-1",
  );

  // The vk resolver returns the REAL verifying key for the accepted circuit.
  const getVerifyingKey = (id: string): VerifyingKey | null =>
    id === CIRCUIT_ID ? realVk : null;

  check(
    "manifest with real vk_hash signs and verifies",
    verifyManifest(manifest, authorityPk).ok === true,
  );

  // =========================================================================
  // POSITIVE — genuine proof, all five §8.2 steps execute and pass.
  //   step 1  manifest signature valid
  //   step 2  issuer is a federation member
  //   step 3  circuit is an accepted circuit
  //   step 4  resolved vk hashes to the manifest's registered vk_hash
  //   step 5  REAL groth16.verify pairing check returns TRUE
  // =========================================================================
  {
    const r = await verifyCrossIssuerProof(
      realProof,
      manifest,
      getVerifyingKey,
      authorityPk,
    );
    check(
      "POSITIVE — genuine cross-issuer proof passes all five §8.2 steps "
        + "(incl. real Groth16 verify)",
      r.ok === true && r.reason === "verified",
      r.reason,
    );
  }

  // =========================================================================
  // NEGATIVE — same code path, a mutated proof must be rejected at step 5.
  // We flip one public input; the federation gate (steps 1-4) still passes
  // because membership / circuit / vk_hash are untouched, so the request
  // reaches the Groth16 pairing check — which now fails.
  // =========================================================================
  {
    const mutatedInputs = realProof.public_inputs.slice();
    // statement-level signal at index 3 ("threshold" = 3) is bumped by one.
    mutatedInputs[3] = (BigInt(mutatedInputs[3]) + 1n).toString();
    const mutatedProof: R4ProofObject = {
      ...realProof,
      public_inputs: mutatedInputs,
    };
    const r = await verifyCrossIssuerProof(
      mutatedProof,
      manifest,
      getVerifyingKey,
      authorityPk,
    );
    check(
      "NEGATIVE — mutated proof reaches step 5 and Groth16 rejects it",
      r.ok === false && r.reason.startsWith("groth16_"),
      r.reason,
    );
  }

  // =========================================================================
  // NEGATIVE — mutated Groth16 proof point. Tampering pi_a must also fail the
  // pairing check (proves it is the cryptography, not just the public input,
  // being checked).
  // =========================================================================
  {
    const badPoint = JSON.parse(JSON.stringify(realProof.proof)) as any;
    badPoint.pi_a[0] = (BigInt(badPoint.pi_a[0]) + 1n).toString();
    const tamperedProof: R4ProofObject = { ...realProof, proof: badPoint };
    const r = await verifyCrossIssuerProof(
      tamperedProof,
      manifest,
      getVerifyingKey,
      authorityPk,
    );
    check(
      "NEGATIVE — tampered Groth16 proof point is rejected at step 5",
      r.ok === false && r.reason.startsWith("groth16_"),
      r.reason,
    );
  }

  // ── summary ──────────────────────────────────────────────────────────────
  console.log("");
  console.log(`R+4 CROSS-ISSUER E2E: ${pass} passed, ${fail} failed`);
  console.log(
    fail === 0
      ? "R+4 §8.2 cross-issuer verification: END-TO-END SOUND — real Groth16 "
        + "proof accepted, mutated proofs rejected."
      : "R+4 §8.2 cross-issuer verification: FAILED — see [FAIL] lines above.",
  );
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("R+4 CROSS-ISSUER E2E: fatal error —", e);
  process.exit(1);
});
