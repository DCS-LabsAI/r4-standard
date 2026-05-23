// ===========================================================================
// R+4 "Federation Protocol" — manifest SYNC + REVOCATION test suite
// Exercises federation/sync.ts (R+4 spec §8 — multi-node manifest sync).
// ===========================================================================
//
// SCOPE: SINGLE-PROCESS SIMULATION. The "nodes" are in-memory objects and
// `propagate()` is a synchronous loop — there is no real network, no gossip
// transport, and no partition/liveness handling. This suite validates the
// convergence / fork-rejection / revocation LOGIC only. See sync.ts header.
//
// Cases:
//   C1  CONVERGENCE          — a valid v2 propagates; all 4 honest nodes adopt
//   C2  STALE-NODE CATCH-UP  — a node left at v1 catches up to v3 via the chain
//   C3  FORK REJECTION       — a same-version fork, a forged signature, and a
//                              broken predecessor chain are all rejected
//   C4  REVOCATION PROPAGATION — revoke an issuer; honest nodes stop accepting
//                                its proofs after the revocation propagates
//
// Run: cd r4-standard/reference && npx tsx federation/test/sync.test.ts
// ===========================================================================

import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import * as ed from "@noble/ed25519";

import {
  buildManifest,
  signManifest,
  updateManifest,
  type SignedManifest,
} from "../manifest.js";
import { vkHash, type R4ProofObject, type VerifyingKey } from "../cross-issuer.js";
import {
  makeNode,
  propagate,
  adopt,
  revoke,
  issuerAcceptedBy,
  type FederationNode,
} from "../sync.js";

ed.hashes.sha512 = (...m) => sha512(ed.etc.concatBytes(...m));

let pass = 0;
let fail = 0;
function check(name: string, ok: boolean, detail?: string) {
  console.log(`  ${ok ? "[ ok ]" : "[FAIL]"}  ${name}${detail ? "  — " + detail : ""}`);
  ok ? pass++ : fail++;
}

console.log("R+4 — federation manifest SYNC + REVOCATION test (single-process simulation)\n");

async function main(): Promise<void> {

// ── set up: federation authority + 3 member issuers ────────────────────────
const authoritySk = ed.utils.randomSecretKey();
const authorityPk = bytesToHex(ed.getPublicKey(authoritySk));
const AKEY = "authority-key-1";

function makeIssuer(id: string) {
  const sk = ed.utils.randomSecretKey();
  return { issuer_id: id, issuer_pubkey: bytesToHex(ed.getPublicKey(sk)) };
}
const issuerA = makeIssuer("did:dcs:org-alpha");
const issuerB = makeIssuer("did:dcs:org-beta");
const issuerC = makeIssuer("did:dcs:org-gamma");

const STUB_VK: VerifyingKey = {
  protocol: "groth16", curve: "bn128", nPublic: 8,
  note: "stub vk — sync-layer test only",
};
const CIRCUIT_ID = "r4-threshold-count-v1";
const getVerifyingKey = (id: string): VerifyingKey | null =>
  id === CIRCUIT_ID ? STUB_VK : null;

// ── genesis manifest (v1): 3 members, 1 circuit ────────────────────────────
const v1: SignedManifest = signManifest(
  buildManifest({
    federation_id: "fed:dcs:r4-sync-test",
    members: [issuerA, issuerB, issuerC],
    accepted_circuits: [{ circuit_id: CIRCUIT_ID, vk_hash: vkHash(STUB_VK) }],
  }),
  authoritySk,
  AKEY,
);

// =========================================================================
// C1 — CONVERGENCE
// 4 honest nodes all start at v1. A valid v2 (adds a circuit) is propagated.
// Every node verifies it, sees a higher version, confirms the +1 chain link,
// and adopts. The federation converges on v2.
// =========================================================================
{
  const nodes: FederationNode[] = [
    makeNode("node-1", authorityPk, v1),
    makeNode("node-2", authorityPk, v1),
    makeNode("node-3", authorityPk, v1),
    makeNode("node-4", authorityPk, v1),
  ];
  const v2 = updateManifest(
    v1,
    { addCircuits: [{ circuit_id: "r4-amount-sum-v1", vk_hash: vkHash({ ...STUB_VK, n: 2 }) }] },
    authoritySk,
    AKEY,
  );
  const r = propagate(nodes, v2);
  const allAdopted = Object.values(r.decisions).every((d) => d.adopted);
  check(
    "C1 — all 4 honest nodes adopt the valid v2 manifest",
    allAdopted,
    `adopted: ${Object.values(r.decisions).filter((d) => d.adopted).length}/4`,
  );
  check(
    "C1 — federation converges on a single version (v2)",
    r.converged && r.convergedVersion === 2,
    `convergedVersion=${r.convergedVersion}`,
  );
}

// =========================================================================
// C2 — STALE-NODE CATCH-UP
// node-stale is left behind at v1 while the federation advances to v3.
// On the next propagation it is offered v3 PLUS the intermediate chain
// [v2, v3]; it validates each link and jumps v1 -> v3 in one round.
// =========================================================================
{
  const v2 = updateManifest(
    v1,
    { addCircuits: [{ circuit_id: "r4-amount-sum-v1", vk_hash: vkHash({ ...STUB_VK, n: 2 }) }] },
    authoritySk,
    AKEY,
  );
  const v3 = updateManifest(
    v2,
    { addCircuits: [{ circuit_id: "r4-range-v1", vk_hash: vkHash({ ...STUB_VK, n: 3 }) }] },
    authoritySk,
    AKEY,
  );

  // up-to-date nodes already at v3; one stale node still at v1.
  const upToDate1 = makeNode("node-1", authorityPk, v3);
  const upToDate2 = makeNode("node-2", authorityPk, v3);
  const stale = makeNode("node-stale", authorityPk, v1);

  check(
    "C2 — stale node starts behind (v1) while federation is at v3",
    stale.current.version === 1 && upToDate1.current.version === 3,
  );

  const r = propagate([upToDate1, upToDate2, stale], v3, [v2, v3]);
  check(
    "C2 — stale node catches up v1 -> v3 in one round via the chain",
    r.decisions["node-stale"].adopted &&
      r.decisions["node-stale"].fromVersion === 1 &&
      r.decisions["node-stale"].toVersion === 3,
    `${r.decisions["node-stale"].reason}`,
  );
  check(
    "C2 — already-current nodes reject the re-offered v3 (not strictly newer)",
    !r.decisions["node-1"].adopted &&
      r.decisions["node-1"].reason.startsWith("fork_or_replay"),
    r.decisions["node-1"].reason,
  );
  check(
    "C2 — whole federation converged on v3 after catch-up",
    r.converged && r.convergedVersion === 3,
    `convergedVersion=${r.convergedVersion}`,
  );
}

// =========================================================================
// C3 — FORK / BYZANTINE REJECTION
// Honest nodes at v1 are attacked three ways. None must displace v1.
// =========================================================================
{
  const v2 = updateManifest(
    v1,
    { addCircuits: [{ circuit_id: "r4-amount-sum-v1", vk_hash: vkHash({ ...STUB_VK, n: 2 }) }] },
    authoritySk,
    AKEY,
  );

  // 3a — SAME-VERSION FORK: a different "v1" minted by the authority. Even
  //      with a valid signature, an honest node already at v1 rejects it
  //      because the version is not strictly higher.
  {
    const node = makeNode("node-fork", authorityPk, v1);
    const forkV1 = signManifest(
      buildManifest({
        federation_id: v1.federation_id,
        members: [issuerA, issuerB], // different membership, same version
        accepted_circuits: v1.accepted_circuits,
      }),
      authoritySk,
      AKEY,
    );
    const d = adopt(node, forkV1);
    check(
      "C3a — same-version fork is rejected; node keeps v1",
      !d.adopted && d.reason.startsWith("fork_or_replay") && node.current.version === 1,
      d.reason,
    );
  }

  // 3b — FORGED SIGNATURE: a structurally perfect v2 signed by an attacker
  //      key, not the federation authority. verifyManifest fails.
  {
    const node = makeNode("node-forged", authorityPk, v1);
    const attackerSk = ed.utils.randomSecretKey();
    const forgedV2 = signManifest(
      buildManifest({
        federation_id: v1.federation_id,
        members: v1.members,
        accepted_circuits: v1.accepted_circuits,
        version: 2,
        predecessor_hash: v2.predecessor_hash, // correct chain link...
      }),
      attackerSk, // ...but signed by the wrong key
      AKEY,
    );
    const d = adopt(node, forgedV2);
    check(
      "C3b — forged-signature manifest is rejected; node keeps v1",
      !d.adopted && d.reason.startsWith("manifest_invalid") && node.current.version === 1,
      d.reason,
    );
  }

  // 3c — BROKEN PREDECESSOR CHAIN: an authority-signed v2 whose
  //      predecessor_hash does not chain from the node's v1.
  {
    const node = makeNode("node-chain", authorityPk, v1);
    const brokenV2 = signManifest(
      buildManifest({
        federation_id: v1.federation_id,
        members: v1.members,
        accepted_circuits: v1.accepted_circuits,
        version: 2,
        predecessor_hash: "sha256:" + "a".repeat(64), // not hash(v1)
      }),
      authoritySk,
      AKEY,
    );
    const d = adopt(node, brokenV2);
    check(
      "C3c — broken predecessor chain is rejected; node keeps v1",
      !d.adopted && d.reason.startsWith("broken_chain") && node.current.version === 1,
      d.reason,
    );
  }

  // 3d — and the genuine v2 IS adopted by the same kind of node (control):
  //      the fork-rejection logic is selective, not blanket-reject.
  {
    const node = makeNode("node-control", authorityPk, v1);
    const d = adopt(node, v2);
    check(
      "C3d — control: the genuine v2 is still adopted (rejection is selective)",
      d.adopted && node.current.version === 2,
      d.reason,
    );
  }
}

// =========================================================================
// C4 — REVOCATION PROPAGATION
// issuerC is revoked at v2. Before propagation, nodes at v1 accept a proof
// from issuerC; after the revocation manifest propagates, every honest node
// rejects issuerC's proof with `issuer_not_member`.
// =========================================================================
{
  const nodes: FederationNode[] = [
    makeNode("node-1", authorityPk, v1),
    makeNode("node-2", authorityPk, v1),
    makeNode("node-3", authorityPk, v1),
  ];

  const proofFromC: R4ProofObject = {
    circuit_id: CIRCUIT_ID,
    statement: { issuer_id: issuerC.issuer_id, threshold: 3 },
    proof: { pi_a: ["1", "2", "1"], pi_b: [["1", "2"], ["3", "4"], ["1", "0"]], pi_c: ["5", "6", "1"] },
    public_inputs: ["1", "2", "3", "4", "5", "6", "7", "8"],
  };

  // BEFORE revocation: issuerC is a member, so the §8.2 check passes the
  // membership gate (it reaches the Groth16 stage; not issuer_not_member).
  const before = await issuerAcceptedBy(nodes[0], proofFromC, getVerifyingKey);
  check(
    "C4 — before revocation: issuerC clears the membership gate",
    before.reason !== `issuer_not_member: ${issuerC.issuer_id}`,
    before.reason,
  );

  // produce the revocation manifest (v2 with issuerC removed) and propagate.
  const { manifest: revManifest, revoked } = await revoke(
    v1,
    issuerC.issuer_id,
    authoritySk,
    AKEY,
  );
  check(
    "C4 — revoke() produced a v2 manifest with issuerC removed",
    revManifest.version === 2 &&
      !revManifest.members.some((m) => m.issuer_id === revoked),
    `revoked ${revoked}`,
  );

  const r = propagate(nodes, revManifest);
  check(
    "C4 — revocation manifest propagated to all honest nodes (converged v2)",
    r.converged && r.convergedVersion === 2,
    `convergedVersion=${r.convergedVersion}`,
  );

  // AFTER revocation: every honest node now rejects issuerC's proof at the
  // membership gate — revocation has propagated.
  let allReject = true;
  let lastReason = "";
  for (const node of nodes) {
    const after = await issuerAcceptedBy(node, proofFromC, getVerifyingKey);
    lastReason = after.reason;
    if (after.ok || after.reason !== `issuer_not_member: ${issuerC.issuer_id}`) {
      allReject = false;
    }
  }
  check(
    "C4 — after revocation: ALL honest nodes reject issuerC's proof (issuer_not_member)",
    allReject,
    lastReason,
  );

  // and a non-revoked issuer (A) is unaffected.
  const proofFromA: R4ProofObject = {
    ...proofFromC,
    statement: { ...proofFromC.statement, issuer_id: issuerA.issuer_id },
  };
  const aAfter = await issuerAcceptedBy(nodes[0], proofFromA, getVerifyingKey);
  check(
    "C4 — non-revoked issuerA still clears the membership gate post-revocation",
    aAfter.reason !== `issuer_not_member: ${issuerA.issuer_id}`,
    aAfter.reason,
  );
}

// ── summary ────────────────────────────────────────────────────────────────
console.log("");
console.log(`R+4 FEDERATION SYNC: ${pass} passed, ${fail} failed`);
console.log(
  fail === 0
    ? "R+4 federation sync layer: SOUND — convergence holds, forks rejected, " +
      "revocation propagates. (Single-process simulation — not a deployed network.)"
    : "R+4 federation sync layer: FAILED — a sync-layer check did not behave as specified.",
);
process.exit(fail === 0 ? 0 : 1);

} // end main()

main().catch((e) => {
  console.error("R+4 FEDERATION SYNC: fatal error —", e);
  process.exit(1);
});
