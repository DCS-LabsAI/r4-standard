// ===========================================================================
// R+4 "Federation Protocol" — MULTI-NODE networking test (multinode.test.ts)
// Exercises federation/node-server.ts — the federation multi-node prototype.
// ===========================================================================
//
// SCOPE / HONESTY NOTICE
// ----------------------
// This test spawns THREE REAL FEDERATION NODE PROCESSES — three independent
// OS processes, each running `tsx federation/node-server.ts`, each an HTTP
// server on its own localhost port. The test driver talks to them ONLY over
// real HTTP via fetch; nodes sync with each other ONLY over real HTTP. There
// are no direct in-process function calls into the node logic.
//
// What it validates over the network:
//   1. 3 nodes start at the genesis manifest (v1)
//   2. a manifest update applied to node-1 -> v2
//   3. /sync makes nodes 2 & 3 converge to v2 over HTTP
//   4. a revocation on node-1 -> v3; /sync -> all 3 nodes hold v3
//   5. a forged/older manifest POSTed to a node is REJECTED; node keeps state
//   6. a cross-issuer proof POSTed to /verify returns a structured result
//
// This is the federation MULTI-NODE PROTOTYPE: real processes, real HTTP, the
// real sync/convergence/revocation protocol. It is NOT production-hardened
// (no TLS, no peer auth, no BFT consensus, not deployed). See node-server.ts.
//
// Run: cd r4-standard/reference && npx tsx federation/test/multinode.test.ts
// ===========================================================================

import { spawn, type ChildProcess } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

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

ed.hashes.sha512 = (...m) => sha512(ed.etc.concatBytes(...m));

let pass = 0;
let fail = 0;
function check(name: string, ok: boolean, detail?: string) {
  console.log(`  ${ok ? "[ ok ]" : "[FAIL]"}  ${name}${detail ? "  — " + detail : ""}`);
  ok ? pass++ : fail++;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const NODE_SERVER = path.resolve(__dirname, "../node-server.ts");

const PORTS = [7401, 7402, 7403];
const procs: ChildProcess[] = [];
const tmpFiles: string[] = [];

// ── small HTTP helpers (the ONLY way the test touches the nodes) ────────────

async function getJson(url: string): Promise<any> {
  const r = await fetch(url);
  return r.json();
}
async function postJson(url: string, body: unknown): Promise<{ status: number; json: any }> {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: r.status, json: await r.json() };
}

async function waitForReady(port: number, timeoutMs = 15000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/health`);
      if (r.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((res) => setTimeout(res, 150));
  }
  return false;
}

function cleanup(): void {
  for (const p of procs) {
    try {
      p.kill("SIGKILL");
    } catch {
      /* ignore */
    }
  }
  for (const f of tmpFiles) {
    try {
      fs.unlinkSync(f);
    } catch {
      /* ignore */
    }
  }
}

async function main(): Promise<void> {
  console.log(
    "R+4 — federation MULTI-NODE test (3 real processes, real HTTP)\n",
  );

  // ── set up: federation authority + 3 member issuers ──────────────────────
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
  const issuerD = makeIssuer("did:dcs:org-delta"); // added at v2

  const STUB_VK: VerifyingKey = {
    protocol: "groth16",
    curve: "bn128",
    nPublic: 8,
    note: "stub vk — multinode test only",
  };
  const CIRCUIT_ID = "r4-threshold-count-v1";

  // ── genesis manifest (v1): 3 members, 1 circuit ──────────────────────────
  const genesis: SignedManifest = signManifest(
    buildManifest({
      federation_id: "fed:dcs:r4-multinode-test",
      members: [issuerA, issuerB, issuerC],
      accepted_circuits: [{ circuit_id: CIRCUIT_ID, vk_hash: vkHash(STUB_VK) }],
    }),
    authoritySk,
    AKEY,
  );

  // ── STEP 1: spawn 3 real federation node processes at v1 ─────────────────
  const peerUrls = PORTS.map((p) => `http://127.0.0.1:${p}`);
  for (let i = 0; i < PORTS.length; i++) {
    const port = PORTS[i];
    const peers = peerUrls.filter((_, j) => j !== i); // all other nodes
    const cfg = {
      node_id: `node-${i + 1}`,
      authorityPk,
      initialManifest: genesis,
      port,
      peers,
    };
    const cfgPath = path.join(os.tmpdir(), `r4-multinode-${process.pid}-${i}.json`);
    fs.writeFileSync(cfgPath, JSON.stringify(cfg));
    tmpFiles.push(cfgPath);

    const child = spawn(
      "npx",
      ["tsx", NODE_SERVER, "--config", cfgPath],
      { stdio: ["ignore", "pipe", "pipe"], env: process.env },
    );
    child.stdout?.on("data", (d) =>
      process.stdout.write(`  [node-${i + 1}] ${d}`),
    );
    child.stderr?.on("data", (d) =>
      process.stderr.write(`  [node-${i + 1} err] ${d}`),
    );
    procs.push(child);
  }

  const ready = await Promise.all(PORTS.map((p) => waitForReady(p)));
  check(
    "STEP 1 — all 3 federation node processes started and answer HTTP",
    ready.every((r) => r === true),
    `ready: ${ready.filter(Boolean).length}/3`,
  );
  if (!ready.every((r) => r)) {
    throw new Error("nodes failed to start — aborting");
  }

  // all 3 report genesis v1 over HTTP
  const v1s = await Promise.all(
    peerUrls.map((u) => getJson(`${u}/manifest`)),
  );
  check(
    "STEP 1 — all 3 nodes hold the genesis manifest (v1) over HTTP",
    v1s.every((m) => m.version === 1),
    `versions: ${v1s.map((m) => m.version).join(",")}`,
  );

  // /peers endpoint
  const peersResp = await getJson(`${peerUrls[0]}/peers`);
  check(
    "STEP 1 — GET /peers lists the 2 configured peer URLs",
    Array.isArray(peersResp.peers) && peersResp.peers.length === 2,
    `peers=${JSON.stringify(peersResp.peers)}`,
  );

  // ── STEP 2: apply a manifest update on node-1 (add a member) -> v2 ───────
  const v2: SignedManifest = updateManifest(
    genesis,
    { addMembers: [issuerD] },
    authoritySk,
    AKEY,
  );
  const post2 = await postJson(`${peerUrls[0]}/manifest`, v2);
  check(
    "STEP 2 — node-1 accepts the v2 update (member added) via POST /manifest",
    post2.json.adopted === true && post2.json.version === 2,
    `${post2.json.reason} (v${post2.json.version})`,
  );

  // ── STEP 3: trigger /sync on node-2 and node-3 -> converge to v2 ─────────
  await postJson(`${peerUrls[1]}/sync`, {});
  await postJson(`${peerUrls[2]}/sync`, {});
  const afterSync2 = await Promise.all(
    peerUrls.map((u) => getJson(`${u}/manifest`)),
  );
  check(
    "STEP 3 — nodes 2 & 3 converged to v2 over HTTP after /sync",
    afterSync2.every((m) => m.version === 2),
    `versions: ${afterSync2.map((m) => m.version).join(",")}`,
  );

  // ── STEP 4: revoke a member on node-1 -> v3; sync -> all hold v3 ─────────
  const v3: SignedManifest = updateManifest(
    v2,
    { removeMembers: [issuerC.issuer_id] }, // revocation
    authoritySk,
    AKEY,
  );
  const post3 = await postJson(`${peerUrls[0]}/manifest`, v3);
  check(
    "STEP 4 — node-1 accepts the v3 revocation (issuerC removed)",
    post3.json.adopted === true && post3.json.version === 3,
    `${post3.json.reason} (v${post3.json.version})`,
  );

  await postJson(`${peerUrls[1]}/sync`, {});
  await postJson(`${peerUrls[2]}/sync`, {});
  const afterSync3 = await Promise.all(
    peerUrls.map((u) => getJson(`${u}/manifest`)),
  );
  check(
    "STEP 4 — all 3 nodes hold v3 after revocation propagated over HTTP",
    afterSync3.every((m) => m.version === 3),
    `versions: ${afterSync3.map((m) => m.version).join(",")}`,
  );
  check(
    "STEP 4 — revoked issuerC is absent from every node's v3 manifest",
    afterSync3.every(
      (m) => !m.members.some((x: any) => x.issuer_id === issuerC.issuer_id),
    ),
    "issuerC removed network-wide",
  );

  // ── STEP 5a: forged manifest (wrong signer) POSTed -> rejected ───────────
  const attackerSk = ed.utils.randomSecretKey();
  const forgedV4 = signManifest(
    buildManifest({
      federation_id: genesis.federation_id,
      members: [issuerA], // attacker's chosen membership
      accepted_circuits: genesis.accepted_circuits,
      version: 4,
      predecessor_hash: "sha256:" + "a".repeat(64),
    }),
    attackerSk, // NOT the federation authority
    AKEY,
  );
  const postForged = await postJson(`${peerUrls[0]}/manifest`, forgedV4);
  const node1AfterForged = await getJson(`${peerUrls[0]}/manifest`);
  check(
    "STEP 5 — forged-signature manifest is REJECTED by POST /manifest",
    postForged.json.adopted === false &&
      postForged.json.reason.startsWith("manifest_invalid"),
    postForged.json.reason,
  );
  check(
    "STEP 5 — node-1 keeps v3 after rejecting the forged manifest",
    node1AfterForged.version === 3,
    `version=${node1AfterForged.version}`,
  );

  // ── STEP 5b: stale/older manifest (v2 again) POSTed -> rejected ──────────
  const postStale = await postJson(`${peerUrls[1]}/manifest`, v2);
  const node2AfterStale = await getJson(`${peerUrls[1]}/manifest`);
  check(
    "STEP 5 — stale (older) manifest is REJECTED; node keeps its version",
    postStale.json.adopted === false &&
      (postStale.json.reason.startsWith("stale") ||
        postStale.json.reason.startsWith("fork_or_replay")) &&
      node2AfterStale.version === 3,
    `${postStale.json.reason} (kept v${node2AfterStale.version})`,
  );

  // ── STEP 6: POST a cross-issuer proof to /verify -> structured result ────
  const proof: R4ProofObject = {
    circuit_id: CIRCUIT_ID,
    statement: { issuer_id: issuerA.issuer_id, threshold: 3 },
    proof: {
      pi_a: ["1", "2", "1"],
      pi_b: [["1", "2"], ["3", "4"], ["1", "0"]],
      pi_c: ["5", "6", "1"],
    },
    public_inputs: ["1", "2", "3", "4", "5", "6", "7", "8"],
  };
  const verifyResp = await postJson(`${peerUrls[0]}/verify`, proof);
  check(
    "STEP 6 — POST /verify returns a structured {ok, reason} result",
    verifyResp.status === 200 &&
      typeof verifyResp.json.ok === "boolean" &&
      typeof verifyResp.json.reason === "string",
    `ok=${verifyResp.json.ok} reason=${verifyResp.json.reason}`,
  );

  // and: a proof from the REVOKED issuerC must be rejected at the
  // membership gate by every node's current (v3) manifest.
  const revokedProof: R4ProofObject = {
    ...proof,
    statement: { ...proof.statement, issuer_id: issuerC.issuer_id },
  };
  const revokedResp = await postJson(`${peerUrls[2]}/verify`, revokedProof);
  check(
    "STEP 6 — /verify rejects a proof from the revoked issuerC (issuer_not_member)",
    revokedResp.json.ok === false &&
      revokedResp.json.reason.startsWith("issuer_not_member"),
    revokedResp.json.reason,
  );
}

main()
  .then(() => {
    console.log("");
    console.log(`R+4 MULTI-NODE: ${pass} passed, ${fail} failed`);
    console.log(
      fail === 0
        ? "R+4 federation multi-node prototype: SOUND — convergence, " +
            "revocation and fork-rejection all hold across real processes " +
            "over real HTTP. (Prototype — not production-hardened.)"
        : "R+4 federation multi-node prototype: FAILED — a networked check " +
            "did not behave as specified.",
    );
    cleanup();
    process.exit(fail === 0 ? 0 : 1);
  })
  .catch((e) => {
    console.error("R+4 MULTI-NODE: fatal error —", e);
    console.log(`\nR+4 MULTI-NODE: ${pass} passed, ${fail + 1} failed`);
    cleanup();
    process.exit(1);
  });
