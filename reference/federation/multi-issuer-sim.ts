// ===========================================================================
// R+4 "Federation Protocol" — multi-issuer simulation
// R+4 spec §8 — three issuers sharing one federation manifest, in-process.
// ===========================================================================
//
// SCOPE / HONESTY NOTICE
// ----------------------
// This is a SINGLE-PROCESS SIMULATION. It models three independent issuer
// organisations as three Ed25519 keypairs held in local memory, all members
// of one shared, signed federation manifest. It demonstrates the §8.2
// cross-issuer outcome: a proof from a member issuer is ACCEPTED by the
// federation verifier, and a proof from a non-member issuer is REJECTED.
//
// What this is NOT:
//   - it is not a real network: there are no sockets, no transport, no nodes
//   - there is no gossip / manifest sync between the simulated issuers
//   - there is no consensus and no Byzantine fault tolerance
// All three "issuers" run in the same Node.js process and share the same
// manifest object by reference. The cryptography (Ed25519 manifest signing,
// SHA-256 vk hashing, Groth16 pairing check) is REAL; the distribution is
// simulated. Real multi-node federation is v1.0 future work — see README.md.
//
// The genuine proof used here is a DEV-key Groth16 proof loaded from
// federation/fixtures/. Issuer "alpha" is identified with the real issuer of
// that proof so its §8.2 step-5 pairing check actually passes.
//
// Run directly:  npx tsx federation/multi-issuer-sim.ts
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
  type SignedManifest,
} from "./manifest.js";
import {
  verifyCrossIssuerProof,
  vkHash,
  type CrossIssuerResult,
  type GetVerifyingKey,
  type R4ProofObject,
  type VerifyingKey,
} from "./cross-issuer.js";

ed.hashes.sha512 = (...m) => sha512(ed.etc.concatBytes(...m));

// ── a simulated issuer organisation ─────────────────────────────────────────

/**
 * One simulated issuer org: an Ed25519 keypair plus a DID-style id. In a real
 * deployment this would be a separate node with its own network identity.
 */
export interface SimulatedIssuer {
  issuer_id: string;
  sk: Uint8Array;
  issuer_pubkey: string;
}

function makeIssuer(issuer_id: string): SimulatedIssuer {
  const sk = ed.utils.randomSecretKey();
  return { issuer_id, sk, issuer_pubkey: bytesToHex(ed.getPublicKey(sk)) };
}

// ── the simulated federation ────────────────────────────────────────────────

export interface FederationSim {
  /** The signed, shared federation manifest. */
  manifest: SignedManifest;
  /** Federation-authority public key — used to verify the manifest. */
  authorityPk: string;
  /** The three member issuers (kept for inspection / proof construction). */
  issuers: SimulatedIssuer[];
  /** Resolver mapping the accepted circuit_id to its real verifying key. */
  getVerifyingKey: GetVerifyingKey;
  /** circuit_id of the federation's single accepted circuit. */
  circuitId: string;
  /**
   * The federation's cross-issuer verifier. Any party in the federation can
   * call this to decide whether to accept a proof from any other issuer.
   */
  verify(proof: R4ProofObject): Promise<CrossIssuerResult>;
}

/**
 * Build a 3-issuer federation in one process. The first issuer is bound to
 * the identity of the real dev-key proof in federation/fixtures/ so that a
 * genuine, fully-passing §8.2 proof can be demonstrated.
 */
export function buildFederationSim(): FederationSim {
  const HERE = dirname(fileURLToPath(import.meta.url));
  const FIXTURES = join(HERE, "fixtures");

  const realVk: VerifyingKey = JSON.parse(
    readFileSync(join(FIXTURES, "verification_key.json"), "utf8"),
  );
  const realProofFile = JSON.parse(
    readFileSync(join(FIXTURES, "proof.json"), "utf8"),
  );
  const circuitId: string = realProofFile.circuit_id;
  const realIssuerId: string = realProofFile.statement.issuer_id;

  // federation authority
  const authoritySk = ed.utils.randomSecretKey();
  const authorityPk = bytesToHex(ed.getPublicKey(authoritySk));

  // Three simulated issuers. Issuer "alpha" IS the real proof's issuer so its
  // §8.2 pairing check can genuinely pass; beta and gamma are extra members.
  const alpha = makeIssuer(realIssuerId);
  const beta = makeIssuer("did:dcs:org-beta");
  const gamma = makeIssuer("did:dcs:org-gamma");
  const issuers = [alpha, beta, gamma];

  const manifest = signManifest(
    buildManifest({
      federation_id: "fed:dcs:r4-multi-issuer-sim",
      members: issuers.map((i) => ({
        issuer_id: i.issuer_id,
        issuer_pubkey: i.issuer_pubkey,
      })),
      accepted_circuits: [{ circuit_id: circuitId, vk_hash: vkHash(realVk) }],
    }),
    authoritySk,
    "authority-key-1",
  );

  const getVerifyingKey: GetVerifyingKey = (id) =>
    id === circuitId ? realVk : null;

  return {
    manifest,
    authorityPk,
    issuers,
    getVerifyingKey,
    circuitId,
    verify: (proof) =>
      verifyCrossIssuerProof(proof, manifest, getVerifyingKey, authorityPk),
  };
}

/**
 * The genuine cross-issuer proof: the real dev-key Groth16 proof from
 * federation/fixtures/, presented as an R+4 proof object. Its issuer is a
 * federation member, so all five §8.2 steps execute and step 5 passes.
 *
 * The fixture's stale embedded `vk_hash` (computed by an older pipeline) is
 * intentionally omitted so §8.2 step 4 compares the manifest hash against the
 * freshly recomputed vk hash — the honest cross-issuer check.
 */
export function loadGenuineProof(): R4ProofObject {
  const HERE = dirname(fileURLToPath(import.meta.url));
  const realProofFile = JSON.parse(
    readFileSync(join(HERE, "fixtures", "proof.json"), "utf8"),
  );
  return {
    circuit_id: realProofFile.circuit_id,
    statement: realProofFile.statement,
    proof: realProofFile.proof,
    public_inputs: realProofFile.public_inputs,
  };
}

/**
 * A structurally identical proof attributed to a NON-MEMBER issuer. The
 * federation verifier must reject it at §8.2 step 2 (issuer_not_member),
 * before the cryptographic check is ever reached.
 */
export function makeNonMemberProof(genuine: R4ProofObject): R4ProofObject {
  return {
    ...genuine,
    statement: { ...genuine.statement, issuer_id: "did:dcs:org-outsider" },
  };
}

// ── runnable demo ────────────────────────────────────────────────────────────

async function demo(): Promise<void> {
  console.log(
    "R+4 — multi-issuer federation SIMULATION (single process, 3 issuers)\n",
  );

  const fed = buildFederationSim();
  console.log(`  federation: ${fed.manifest.federation_id}`);
  console.log(`  members (${fed.issuers.length}):`);
  for (const i of fed.issuers) {
    console.log(`    - ${i.issuer_id}`);
  }
  console.log(`  accepted circuit: ${fed.circuitId}\n`);

  const genuine = loadGenuineProof();

  // member issuer A submits its genuine proof → accepted by the federation.
  const accepted = await fed.verify(genuine);
  console.log(
    `  proof from MEMBER  ${genuine.statement.issuer_id}`
      + `\n    -> ${accepted.ok ? "ACCEPTED" : "REJECTED"}  (${accepted.reason})`,
  );

  // a non-member issuer submits the same proof → rejected by the federation.
  const outsider = makeNonMemberProof(genuine);
  const rejected = await fed.verify(outsider);
  console.log(
    `  proof from NON-MEMBER ${outsider.statement.issuer_id}`
      + `\n    -> ${rejected.ok ? "ACCEPTED" : "REJECTED"}  (${rejected.reason})\n`,
  );

  const ok =
    accepted.ok === true &&
    accepted.reason === "verified" &&
    rejected.ok === false &&
    rejected.reason.startsWith("issuer_not_member");

  console.log(
    ok
      ? "R+4 multi-issuer simulation: SOUND — member proof accepted, "
        + "non-member proof rejected."
      : "R+4 multi-issuer simulation: FAILED — unexpected verification outcome.",
  );
  process.exit(ok ? 0 : 1);
}

// Run the demo only when this file is executed directly, not when imported.
if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === process.argv[1]
) {
  demo().catch((e) => {
    console.error("R+4 multi-issuer simulation: fatal error —", e);
    process.exit(1);
  });
}
