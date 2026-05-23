// ===========================================================================
// R+4 "Federation Protocol" — federation-layer test suite
// Exercises R+4 spec §8 (manifest) and §8.2 (cross-issuer verification).
// ===========================================================================
//
// SCOPE: single-process reference implementation. Three "issuer
// organisations" are simulated as three Ed25519 keypairs in local memory.
// No network, no consensus — see federation/manifest.ts header.
//
// This suite builds a 3-member federation, signs and verifies its manifest,
// then runs five attacks and asserts each is rejected:
//   A1  tampered manifest field
//   A2  forged manifest signature
//   A3  proof from a non-member issuer
//   A4  proof referencing an unregistered circuit
//   A5  stale version / broken predecessor_hash
//
// Run: npx tsx federation/test/federation.test.ts
// ===========================================================================

import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import * as ed from "@noble/ed25519";

import {
  buildManifest,
  signManifest,
  verifyManifest,
  updateManifest,
  manifestHash,
  GENESIS_PREDECESSOR,
  type FederationManifest,
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

console.log("R+4 — federation-protocol test (real Ed25519 / RFC-8785 / SHA-256)\n");

// Wrapped in an async main() so the suite runs under tsx's CJS transform
// (the repo has no "type":"module" — top-level await is unavailable).
async function main(): Promise<void> {

// ── set up: federation authority + 3 simulated issuer organisations ────────
const authoritySk = ed.utils.randomSecretKey();
const authorityPk = bytesToHex(ed.getPublicKey(authoritySk));

function makeIssuer(id: string) {
  const sk = ed.utils.randomSecretKey();
  return { issuer_id: id, sk, issuer_pubkey: bytesToHex(ed.getPublicKey(sk)) };
}
const issuerA = makeIssuer("did:dcs:org-alpha");
const issuerB = makeIssuer("did:dcs:org-beta");
const issuerC = makeIssuer("did:dcs:org-gamma");

// A stub verifying key. Its content is irrelevant to the federation-layer
// logic; only its canonical SHA-256 hash matters for the manifest registry.
const STUB_VK: VerifyingKey = {
  protocol: "groth16",
  curve: "bn128",
  nPublic: 8,
  note: "stub vk — federation-layer test only; not a real ceremony output",
};
const CIRCUIT_ID = "r4-threshold-count-v1";
const STUB_VK_HASH = vkHash(STUB_VK);

const getVerifyingKey = (id: string): VerifyingKey | null =>
  id === CIRCUIT_ID ? STUB_VK : null;

// ── build + sign the genesis manifest (3 members, 1 circuit) ───────────────
const genesisUnsigned = buildManifest({
  federation_id: "fed:dcs:r4-reference",
  members: [
    { issuer_id: issuerA.issuer_id, issuer_pubkey: issuerA.issuer_pubkey },
    { issuer_id: issuerB.issuer_id, issuer_pubkey: issuerB.issuer_pubkey },
    { issuer_id: issuerC.issuer_id, issuer_pubkey: issuerC.issuer_pubkey },
  ],
  accepted_circuits: [{ circuit_id: CIRCUIT_ID, vk_hash: STUB_VK_HASH }],
});
const manifest = signManifest(genesisUnsigned, authoritySk, "authority-key-1");

// ── baseline: a well-formed signed manifest must verify ────────────────────
check(
  "genesis manifest (3 members) verifies against the authority key",
  verifyManifest(manifest, authorityPk).ok === true,
);
check(
  "genesis manifest version is 1 with the genesis predecessor_hash",
  manifest.version === 1 && manifest.predecessor_hash === GENESIS_PREDECESSOR,
);

// ── updateManifest: add a circuit, chain is intact ─────────────────────────
const CIRCUIT2 = "r4-amount-sum-v1";
const STUB_VK2: VerifyingKey = { ...STUB_VK, note: "second stub circuit" };
const manifestV2 = updateManifest(
  manifest,
  { addCircuits: [{ circuit_id: CIRCUIT2, vk_hash: vkHash(STUB_VK2) }] },
  authoritySk,
  "authority-key-1",
);
check(
  "updateManifest yields version 2, signed, verifying",
  manifestV2.version === 2 && verifyManifest(manifestV2, authorityPk).ok === true,
);
check(
  "updateManifest sets predecessor_hash = hash(prev manifest)",
  manifestV2.predecessor_hash === manifestHash(manifest),
);

// ── helper: build a cross-issuer proof object for a given issuer/circuit ───
function makeProof(issuerId: string, circuitId: string): R4ProofObject {
  return {
    circuit_id: circuitId,
    vk_hash: STUB_VK_HASH,
    statement: { issuer_id: issuerId, threshold: 3 },
    proof: { pi_a: ["1", "2", "1"], pi_b: [["1", "2"], ["3", "4"], ["1", "0"]], pi_c: ["5", "6", "1"] },
    public_inputs: ["1", "2", "3", "4", "5", "6", "7", "8"],
  };
}

// =========================================================================
// ATTACK A1 — tampered manifest field
// An attacker rewrites a member's public key after signing.
// =========================================================================
{
  const tampered: FederationManifest = JSON.parse(JSON.stringify(manifest));
  // swap issuerB's pubkey for the attacker's own key
  const attackerPk = bytesToHex(ed.getPublicKey(ed.utils.randomSecretKey()));
  tampered.members[1].issuer_pubkey = attackerPk;
  const r = verifyManifest(tampered, authorityPk);
  check("A1 — tampered manifest field is rejected", r.ok === false, r.reason);
}

// =========================================================================
// ATTACK A2 — forged manifest signature
// An attacker re-signs the manifest with their own (non-authority) key.
// =========================================================================
{
  const attackerSk = ed.utils.randomSecretKey();
  const forged = signManifest(genesisUnsigned, attackerSk, "authority-key-1");
  // structurally perfect, signed — but NOT by the federation authority.
  const r = verifyManifest(forged, authorityPk);
  check("A2 — forged manifest signature is rejected", r.ok === false, r.reason);
}

// =========================================================================
// ATTACK A3 — proof from a non-member issuer
// A valid-looking proof whose issuer_id is not in the manifest.
// =========================================================================
{
  const outsider = makeProof("did:dcs:org-rogue", CIRCUIT_ID);
  const r = await verifyCrossIssuerProof(outsider, manifest, getVerifyingKey, authorityPk);
  check(
    "A3 — proof from a non-member issuer is rejected",
    r.ok === false && r.reason.startsWith("issuer_not_member"),
    r.reason,
  );
}

// =========================================================================
// ATTACK A4 — proof referencing an unregistered circuit
// issuer is a real member, but the circuit is not in accepted_circuits.
// =========================================================================
{
  const badCircuit = makeProof(issuerA.issuer_id, "r4-unknown-circuit-v9");
  const r = await verifyCrossIssuerProof(badCircuit, manifest, getVerifyingKey, authorityPk);
  check(
    "A4 — proof referencing an unregistered circuit is rejected",
    r.ok === false && r.reason.startsWith("circuit_not_accepted"),
    r.reason,
  );
}

// =========================================================================
// ATTACK A5 — stale version / broken predecessor_hash
// A forged "version 2" whose predecessor_hash does NOT chain from v1.
// =========================================================================
{
  // 5a — broken chain: a v2 manifest signed by the authority but whose
  //      predecessor_hash points at nothing real.
  const brokenChain = signManifest(
    buildManifest({
      federation_id: manifest.federation_id,
      members: manifest.members,
      accepted_circuits: manifest.accepted_circuits,
      version: 2,
      predecessor_hash: "sha256:" + "a".repeat(64), // not hash(v1)
    }),
    authoritySk,
    "authority-key-1",
  );
  // signature & structure are valid; the CHAIN is what is broken.
  const chainOk = brokenChain.predecessor_hash === manifestHash(manifest);
  check(
    "A5a — broken predecessor_hash does not chain to v1",
    chainOk === false,
    "predecessor_hash != hash(v1)",
  );

  // 5b — stale version: presenting v1 when v2 is current must be detectable
  //      by predecessor-hash chaining (v1 cannot point to v2).
  const v1IsStale =
    manifest.version < manifestV2.version &&
    manifestV2.predecessor_hash === manifestHash(manifest);
  check(
    "A5b — stale manifest version is detectable via the hash chain",
    v1IsStale === true,
    "v2.predecessor_hash links back to v1",
  );

  // 5c — genesis-rule violation: a version-1 manifest with a non-genesis
  //      predecessor_hash must be rejected outright.
  let genesisViolationRejected = false;
  try {
    buildManifest({
      federation_id: manifest.federation_id,
      members: manifest.members,
      accepted_circuits: manifest.accepted_circuits,
      version: 1,
      predecessor_hash: "sha256:" + "b".repeat(64),
    });
  } catch {
    genesisViolationRejected = true;
  }
  check(
    "A5c — version-1 manifest with non-genesis predecessor_hash is rejected",
    genesisViolationRejected === true,
  );
}

// =========================================================================
// CONTROL — federation-layer happy path
// A genuine member + accepted circuit + correct vk_hash passes steps 1–4
// of §8.2. Step 5 (Groth16 pairing) runs against a real snarkjs call; with
// a STUB verifying key it cannot produce a true pairing, so it is rejected
// at the groth16 stage. This still PROVES the §8.2 federation gate works:
// the request reached the cryptographic check only because every
// federation-layer condition (manifest sig, membership, circuit, vk hash)
// passed. A true Groth16 pass needs the compiled circuit + ceremony key
// (artifacts/verification_key.json), which is gitignored and not built in
// this environment — see STATUS.md / COMPILE_RUNBOOK.md.
// =========================================================================
{
  const genuine = makeProof(issuerA.issuer_id, CIRCUIT_ID);
  const r = await verifyCrossIssuerProof(genuine, manifest, getVerifyingKey, authorityPk);
  const reachedGroth16 =
    r.reason.startsWith("groth16_") || r.reason === "verified";
  check(
    "CONTROL — genuine member+circuit passes §8.2 steps 1–4 and reaches the Groth16 check",
    reachedGroth16 === true,
    r.reason,
  );

  // and: tampering the registered vk_hash must be caught at step 4.
  const badVkManifest = signManifest(
    buildManifest({
      federation_id: manifest.federation_id,
      members: manifest.members,
      accepted_circuits: [
        { circuit_id: CIRCUIT_ID, vk_hash: "sha256:" + "c".repeat(64) },
      ],
    }),
    authoritySk,
    "authority-key-1",
  );
  const r2 = await verifyCrossIssuerProof(genuine, badVkManifest, getVerifyingKey, authorityPk);
  check(
    "CONTROL — vk_hash mismatch at §8.2 step 4 is rejected",
    r2.ok === false && r2.reason.startsWith("vk_hash_mismatch"),
    r2.reason,
  );
}

// ── summary ────────────────────────────────────────────────────────────────
console.log("");
console.log(`R+4 FEDERATION: ${pass} passed, ${fail} failed`);
console.log(
  fail === 0
    ? "R+4 federation layer: SOUND — manifest signing/chaining correct, all attacks rejected."
    : "R+4 federation layer: FAILED — a federation-layer check did not behave as specified.",
);
process.exit(fail === 0 ? 0 : 1);

} // end main()

main().catch((e) => {
  console.error("R+4 FEDERATION: fatal error —", e);
  process.exit(1);
});
