// ===========================================================================
// R+4 "Federation Protocol" — persistence + sync-timeout test
// Exercises federation/persistence.ts and its wiring into node-server.ts.
// ===========================================================================
//
// SCOPE
// -----
//   PART A — unit tests of persistence.ts: fileStore round-trip, atomic write,
//            corrupt-file tolerance, and chooseBootManifest's version + crypto
//            gates.
//   PART B — restart recovery: start a node with a statePath, adopt a newer
//            manifest, stop it, start a fresh node on the same statePath, and
//            confirm it recovers the adopted manifest instead of reverting to
//            its initial one. Control: a node with no statePath does NOT
//            recover.
//   PART C — sync timeout: point a node at a peer that accepts the connection
//            but never responds, and confirm POST /sync returns "timeout"
//            quickly instead of hanging.
//
// Run: cd r4-standard/reference && npx tsx federation/test/persistence.test.ts
// ===========================================================================

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as http from "node:http";

import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import * as ed from "@noble/ed25519";

import {
  buildManifest,
  signManifest,
  updateManifest,
  type SignedManifest,
} from "../manifest.js";
import { vkHash, type VerifyingKey } from "../cross-issuer.js";
import { startNode, type RunningNode } from "../node-server.js";
import { fileStore, memoryStore, chooseBootManifest } from "../persistence.js";

ed.hashes.sha512 = (...m) => sha512(ed.etc.concatBytes(...m));

let pass = 0;
let fail = 0;
function check(name: string, ok: boolean, detail?: string): void {
  console.log(`  ${ok ? "[ ok ]" : "[FAIL]"}  ${name}${detail ? "  — " + detail : ""}`);
  ok ? pass++ : fail++;
}

async function main(): Promise<void> {
  console.log("R+4 — federation PERSISTENCE + sync-timeout test\n");

  // ── keys + manifests ─────────────────────────────────────────────────────
  const authoritySk = ed.utils.randomSecretKey();
  const authorityPk = bytesToHex(ed.getPublicKey(authoritySk));
  const AKEY = "authority-key-1";
  const STUB_VK: VerifyingKey = {
    protocol: "groth16",
    curve: "bn128",
    nPublic: 8,
    note: "stub vk — persistence test only",
  };
  const mkIssuer = (id: string) => ({
    issuer_id: id,
    issuer_pubkey: bytesToHex(ed.getPublicKey(ed.utils.randomSecretKey())),
  });
  const issuerA = mkIssuer("did:dcs:org-alpha");
  const issuerB = mkIssuer("did:dcs:org-beta");
  const issuerC = mkIssuer("did:dcs:org-gamma");

  const genesis: SignedManifest = signManifest(
    buildManifest({
      federation_id: "fed:dcs:r4-persistence-test",
      members: [issuerA, issuerB],
      accepted_circuits: [
        { circuit_id: "r4-threshold-count-v1", vk_hash: vkHash(STUB_VK) },
      ],
    }),
    authoritySk,
    AKEY,
  );
  const v2: SignedManifest = updateManifest(
    genesis,
    { addMembers: [issuerC] },
    authoritySk,
    AKEY,
  );

  // ── PART A — persistence.ts unit tests ───────────────────────────────────
  console.log("PART A — persistence.ts unit tests");

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "r4-persist-"));
  const store = fileStore(dir);

  check("A1 — fileStore.loadManifest() is null when nothing is saved", store.loadManifest() === null);
  check("A2 — memoryStore.loadManifest() is always null", memoryStore.loadManifest() === null);

  store.saveManifest(v2);
  const loaded = store.loadManifest();
  check("A3 — fileStore round-trips a saved manifest", loaded?.version === 2, `v${loaded?.version}`);

  const leftovers = fs.readdirSync(dir).filter((f) => f.includes(".tmp"));
  check("A4 — atomic write leaves no .tmp file behind", leftovers.length === 0, leftovers.join(",") || "none");

  fs.writeFileSync(path.join(dir, "manifest.json"), "{not valid json");
  check("A5 — a corrupt state file loads as null (no crash)", store.loadManifest() === null);
  store.saveManifest(v2); // restore good state

  const c1 = chooseBootManifest(store, genesis, authorityPk);
  check(
    "A6 — chooseBootManifest restores the newer persisted manifest",
    c1.restored === true && c1.manifest.version === 2,
    `restored=${c1.restored} v${c1.manifest.version}`,
  );

  const storeOld = fileStore(fs.mkdtempSync(path.join(os.tmpdir(), "r4-persist-old-")));
  storeOld.saveManifest(genesis);
  const c2 = chooseBootManifest(storeOld, genesis, authorityPk);
  check(
    "A7 — chooseBootManifest does NOT restore a non-newer manifest",
    c2.restored === false && c2.manifest.version === 1,
    `restored=${c2.restored}`,
  );

  const wrongPk = bytesToHex(ed.getPublicKey(ed.utils.randomSecretKey()));
  const c3 = chooseBootManifest(store, genesis, wrongPk);
  check(
    "A8 — chooseBootManifest ignores a manifest failing the signature check",
    c3.restored === false,
    `restored=${c3.restored} (crypto beats disk)`,
  );

  // ── PART B — restart recovery ────────────────────────────────────────────
  console.log("\nPART B — restart recovery via startNode");

  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "r4-node-state-"));
  // A distinct port per node — each startNode/close cycle is a separate
  // "restart", and reusing one port would let undici reuse a pooled
  // connection to the previous (closed) server.
  const url = (p: number) => `http://127.0.0.1:${p}`;

  let node: RunningNode | null = null;
  const hangServer = http.createServer(() => {
    /* accepts the connection but deliberately never responds */
  });

  try {
    node = await startNode({
      node_id: "persist-node-1",
      authorityPk,
      initialManifest: genesis,
      port: 7471,
      peers: [],
      statePath: stateDir,
    });
    const m1 = await (await fetch(`${url(7471)}/manifest`)).json();
    check("B1 — fresh node boots at genesis v1", m1.version === 1, `v${m1.version}`);

    const adoptResp = await fetch(`${url(7471)}/manifest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(v2),
    });
    const adoptJson = await adoptResp.json();
    check(
      "B2 — node adopts v2 via POST /manifest",
      adoptJson.adopted === true && adoptJson.version === 2,
      `${adoptResp.status} v${adoptJson.version}`,
    );

    const health = await (await fetch(`${url(7471)}/health`)).json();
    check("B3 — /health reports persistence enabled", health.persistence === true, `persistence=${health.persistence}`);

    await node.close();
    node = null;

    // restart — fresh node on a new port, SAME statePath, SAME initial genesis
    node = await startNode({
      node_id: "persist-node-1",
      authorityPk,
      initialManifest: genesis,
      port: 7473,
      peers: [],
      statePath: stateDir,
    });
    const m2 = await (await fetch(`${url(7473)}/manifest`)).json();
    check("B4 — restarted node recovers v2 from disk (not initial v1)", m2.version === 2, `v${m2.version}`);
    await node.close();
    node = null;

    // control — a node with no statePath must NOT recover
    node = await startNode({
      node_id: "persist-node-1",
      authorityPk,
      initialManifest: genesis,
      port: 7474,
      peers: [],
    });
    const m3 = await (await fetch(`${url(7474)}/manifest`)).json();
    check("B5 — node without statePath boots at initial v1 (no disk state)", m3.version === 1, `v${m3.version}`);
    await node.close();
    node = null;

    // ── PART C — sync timeout ──────────────────────────────────────────────
    console.log("\nPART C — sync timeout against a hung peer");

    await new Promise<void>((r) => hangServer.listen(7472, "127.0.0.1", () => r()));
    node = await startNode({
      node_id: "persist-node-1",
      authorityPk,
      initialManifest: genesis,
      port: 7475,
      peers: ["http://127.0.0.1:7472"],
      syncTimeoutMs: 800,
    });
    const t0 = Date.now();
    const syncResp = await (
      await fetch(`${url(7475)}/sync`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      })
    ).json();
    const elapsed = Date.now() - t0;
    const peerErr = syncResp.peersContacted?.[0]?.error;
    check(
      "C1 — /sync against a hung peer reports 'timeout' (does not hang)",
      peerErr === "timeout",
      `error=${peerErr} in ${elapsed}ms`,
    );
    check("C2 — /sync settled within the timeout budget", elapsed < 3000, `${elapsed}ms`);
    await node.close();
    node = null;
  } finally {
    if (node) await node.close();
    hangServer.close();
  }

  // ── summary ──────────────────────────────────────────────────────────────
  console.log(`\nR+4 PERSISTENCE: ${pass} passed, ${fail} failed`);
  if (fail > 0) {
    process.exitCode = 1;
  } else {
    console.log(
      "R+4 federation persistence: SOUND — an adopted manifest survives a " +
        "restart, a forged or stale persisted manifest is ignored, and a hung " +
        "peer cannot stall a sync round. (v1.0 hardening — manifest persistence " +
        "+ sync timeout landed; replay-ledger persistence + BFT consensus still ahead.)",
    );
  }
}

main().catch((e) => {
  console.error("[persistence.test] fatal:", e);
  process.exit(1);
});
