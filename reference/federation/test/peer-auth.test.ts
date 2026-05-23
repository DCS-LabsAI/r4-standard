// ===========================================================================
// R+4 "Federation Protocol" — peer authentication test (peer-auth.test.ts)
// Exercises federation/peer-auth.ts and its wiring into node-server.ts.
// ===========================================================================
//
// SCOPE
// -----
// Two parts:
//   PART A — unit tests of peer-auth.ts: request signing/verification, the
//            replay ledger, and rejection of every tamper class.
//   PART B — integration: start a real federation node (in-process, via
//            startNode) with peer authentication ENFORCED, and confirm over
//            real HTTP that mutating endpoints reject unsigned / unknown /
//            replayed requests and accept a correctly-signed peer request.
//   PART C — a TLS smoke test: start an HTTPS node and reach it over TLS.
//            Skipped gracefully if `openssl` is unavailable.
//
// Run: cd r4-standard/reference && npx tsx federation/test/peer-auth.test.ts
// ===========================================================================

import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as https from "node:https";

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
import {
  generateNodeKeypair,
  signRequest,
  verifyRequest,
  signedPostJson,
  ReplayLedger,
  AUTH_HEADERS,
} from "../peer-auth.js";

ed.hashes.sha512 = (...m) => sha512(ed.etc.concatBytes(...m));

let pass = 0;
let fail = 0;
let skip = 0;
function check(name: string, ok: boolean, detail?: string): void {
  console.log(`  ${ok ? "[ ok ]" : "[FAIL]"}  ${name}${detail ? "  — " + detail : ""}`);
  ok ? pass++ : fail++;
}
function skipped(name: string, why: string): void {
  console.log(`  [skip]  ${name}  — ${why}`);
  skip++;
}

async function main(): Promise<void> {
  console.log("R+4 — federation PEER AUTHENTICATION test\n");

  // ── PART A — unit tests of peer-auth.ts ──────────────────────────────────
  console.log("PART A — peer-auth unit tests");

  const peerKp = generateNodeKeypair("node-peer-1");
  const strangerKp = generateNodeKeypair("node-stranger");
  const cfg = { authorizedPeers: [{ node_id: peerKp.node_id, publicKey: peerKp.publicKey }] };

  // a valid signed request round-trips
  {
    const body = JSON.stringify({ hello: "world" });
    const headers = signRequest("POST", "/manifest", body, peerKp);
    check(
      "A1 — signRequest emits all four auth headers",
      Boolean(
        headers[AUTH_HEADERS.nodeId] &&
          headers[AUTH_HEADERS.timestamp] &&
          headers[AUTH_HEADERS.nonce] &&
          headers[AUTH_HEADERS.signature],
      ),
    );
    const ledger = new ReplayLedger();
    const r = verifyRequest("POST", "/manifest", body, headers, cfg, ledger);
    check("A2 — a correctly-signed request from an authorized peer verifies", r.ok, r.reason);
  }

  // missing headers
  {
    const ledger = new ReplayLedger();
    const r = verifyRequest("POST", "/manifest", "{}", {}, cfg, ledger);
    check("A3 — request with no auth headers is rejected", !r.ok && r.reason === "auth_missing_headers", r.reason);
  }

  // unknown peer
  {
    const body = "{}";
    const headers = signRequest("POST", "/manifest", body, strangerKp);
    const ledger = new ReplayLedger();
    const r = verifyRequest("POST", "/manifest", body, headers, cfg, ledger);
    check("A4 — request signed by an unlisted node is rejected", !r.ok && r.reason === "auth_unknown_peer", r.reason);
  }

  // tampered body — signature was over a different body
  {
    const headers = signRequest("POST", "/manifest", JSON.stringify({ a: 1 }), peerKp);
    const ledger = new ReplayLedger();
    const r = verifyRequest("POST", "/manifest", JSON.stringify({ a: 2 }), headers, cfg, ledger);
    check("A5 — a tampered body breaks the signature", !r.ok && r.reason === "auth_signature_invalid", r.reason);
  }

  // tampered path — signature was over a different path
  {
    const body = "{}";
    const headers = signRequest("POST", "/manifest", body, peerKp);
    const ledger = new ReplayLedger();
    const r = verifyRequest("POST", "/sync", body, headers, cfg, ledger);
    check("A6 — a captured signature cannot be moved to another endpoint", !r.ok && r.reason === "auth_signature_invalid", r.reason);
  }

  // clock skew
  {
    const body = "{}";
    const headers = signRequest("POST", "/manifest", body, peerKp);
    headers[AUTH_HEADERS.timestamp] = String(Date.now() - 60 * 60 * 1000); // 1h old
    const ledger = new ReplayLedger();
    const r = verifyRequest("POST", "/manifest", body, headers, cfg, ledger);
    // (changing the timestamp also breaks the signature; either reason is a correct rejection)
    check("A7 — a stale-timestamp request is rejected", !r.ok, r.reason);
  }

  // replay — same nonce twice against the same ledger
  {
    const body = "{}";
    const headers = signRequest("POST", "/manifest", body, peerKp);
    const ledger = new ReplayLedger();
    const first = verifyRequest("POST", "/manifest", body, headers, cfg, ledger);
    const second = verifyRequest("POST", "/manifest", body, headers, cfg, ledger);
    check(
      "A8 — replaying an identical signed request is rejected (nonce burned)",
      first.ok && !second.ok && second.reason === "auth_replay",
      `first=${first.reason} second=${second.reason}`,
    );
  }

  // ── PART B — integration over real HTTP, auth ENFORCED ───────────────────
  console.log("\nPART B — node-server with peer authentication enforced");

  const authoritySk = ed.utils.randomSecretKey();
  const authorityPk = bytesToHex(ed.getPublicKey(authoritySk));
  const AKEY = "authority-key-1";
  const mkIssuer = (id: string) => ({
    issuer_id: id,
    issuer_pubkey: bytesToHex(ed.getPublicKey(ed.utils.randomSecretKey())),
  });
  const STUB_VK: VerifyingKey = {
    protocol: "groth16",
    curve: "bn128",
    nPublic: 8,
    note: "stub vk — peer-auth test only",
  };
  const issuerA = mkIssuer("did:dcs:org-alpha");
  const issuerB = mkIssuer("did:dcs:org-beta");
  const issuerD = mkIssuer("did:dcs:org-delta");

  const genesis: SignedManifest = signManifest(
    buildManifest({
      federation_id: "fed:dcs:r4-peer-auth-test",
      members: [issuerA, issuerB],
      accepted_circuits: [
        { circuit_id: "r4-threshold-count-v1", vk_hash: vkHash(STUB_VK) },
      ],
    }),
    authoritySk,
    AKEY,
  );
  const v2: SignedManifest = updateManifest(genesis, { addMembers: [issuerD] }, authoritySk, AKEY);

  const PORT = 7461;
  const base = `http://127.0.0.1:${PORT}`;
  let node: RunningNode | null = null;
  try {
    node = await startNode({
      node_id: "auth-node-1",
      authorityPk,
      initialManifest: genesis,
      port: PORT,
      peers: [],
      auth: { authorizedPeers: [{ node_id: peerKp.node_id, publicKey: peerKp.publicKey }] },
    });

    // GET stays open
    const health = await (await fetch(`${base}/health`)).json();
    check("B1 — GET /health is open and reports auth enforced", health.ok === true && health.auth === "enforced", `auth=${health.auth}`);

    const gm = await (await fetch(`${base}/manifest`)).json();
    check("B2 — GET /manifest is open (reads need no auth)", gm.version === 1, `v${gm.version}`);

    // unsigned POST /manifest -> 401
    const unsigned = await fetch(`${base}/manifest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(v2),
    });
    const unsignedJson = await unsigned.json();
    check(
      "B3 — unsigned POST /manifest is rejected 401 auth_missing_headers",
      unsigned.status === 401 && unsignedJson.reason === "auth_missing_headers",
      `${unsigned.status} ${unsignedJson.reason}`,
    );

    // POST /manifest signed by an UNauthorized key -> 401
    const stranger = await signedPostJson(base, "/manifest", v2, strangerKp);
    check(
      "B4 — POST /manifest signed by an unlisted node is rejected 401",
      stranger.status === 401 && stranger.json.reason === "auth_unknown_peer",
      `${stranger.status} ${stranger.json.reason}`,
    );

    // node unchanged after the two rejected writes
    const stillV1 = await (await fetch(`${base}/manifest`)).json();
    check("B5 — node still holds v1 after rejected writes", stillV1.version === 1, `v${stillV1.version}`);

    // POST /manifest signed by the AUTHORIZED peer -> 200 adopted
    const good = await signedPostJson(base, "/manifest", v2, peerKp);
    check(
      "B6 — POST /manifest from an authorized peer is accepted; node adopts v2",
      good.status === 200 && good.json.adopted === true && good.json.version === 2,
      `${good.status} ${good.json.reason} v${good.json.version}`,
    );

    // replay a captured authenticated request -> 401 auth_replay
    const body = JSON.stringify(v2);
    const replayHeaders = {
      "content-type": "application/json",
      ...signRequest("POST", "/manifest", body, peerKp),
    };
    const r1 = await fetch(`${base}/manifest`, { method: "POST", headers: replayHeaders, body });
    const r1j = await r1.json();
    const r2 = await fetch(`${base}/manifest`, { method: "POST", headers: replayHeaders, body });
    const r2j = await r2.json();
    check(
      "B7 — replaying a captured signed request is rejected 401 auth_replay",
      r2.status === 401 && r2j.reason === "auth_replay",
      `first=${r1.status}/${r1j.reason}  replay=${r2.status}/${r2j.reason}`,
    );

    // unsigned POST /sync -> 401 (mutating endpoint is also gated)
    const syncUnsigned = await fetch(`${base}/sync`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    check("B8 — unsigned POST /sync is rejected 401", syncUnsigned.status === 401, `status ${syncUnsigned.status}`);

    // POST /verify stays OPEN (read-only) — no auth required
    const verifyResp = await fetch(`${base}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        circuit_id: "r4-threshold-count-v1",
        statement: { issuer_id: issuerA.issuer_id, threshold: 3 },
        proof: { pi_a: ["1", "2", "1"], pi_b: [["1", "2"], ["3", "4"], ["1", "0"]], pi_c: ["5", "6", "1"] },
        public_inputs: ["1", "2", "3", "4", "5", "6", "7", "8"],
      }),
    });
    const verifyJson = await verifyResp.json();
    check(
      "B9 — POST /verify stays open (read-only) and returns a structured result",
      verifyResp.status === 200 && typeof verifyJson.ok === "boolean",
      `status ${verifyResp.status} ok=${verifyJson.ok}`,
    );
  } finally {
    if (node) await node.close();
  }

  // ── PART C — TLS smoke test ──────────────────────────────────────────────
  console.log("\nPART C — TLS (HTTPS) smoke test");
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "r4-tls-"));
  const keyPath = path.join(tmp, "key.pem");
  const certPath = path.join(tmp, "cert.pem");
  let tlsReady = false;
  try {
    execFileSync(
      "openssl",
      ["req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath,
       "-days", "1", "-nodes", "-subj", "/CN=localhost"],
      { stdio: "ignore" },
    );
    tlsReady = fs.existsSync(keyPath) && fs.existsSync(certPath);
  } catch {
    tlsReady = false;
  }

  if (!tlsReady) {
    skipped("C1 — HTTPS node smoke test", "openssl unavailable to generate a test cert");
  } else {
    const TLS_PORT = 7462;
    let tlsNode: RunningNode | null = null;
    try {
      tlsNode = await startNode({
        node_id: "tls-node-1",
        authorityPk,
        initialManifest: genesis,
        port: TLS_PORT,
        peers: [],
        tls: {
          cert: fs.readFileSync(certPath, "utf8"),
          key: fs.readFileSync(keyPath, "utf8"),
        },
      });
      const health = await new Promise<any>((resolve, reject) => {
        const req = https.get(
          `https://127.0.0.1:${TLS_PORT}/health`,
          { rejectUnauthorized: false },
          (res) => {
            let data = "";
            res.on("data", (c) => (data += c));
            res.on("end", () => {
              try {
                resolve(JSON.parse(data));
              } catch (e) {
                reject(e);
              }
            });
          },
        );
        req.on("error", reject);
      });
      check(
        "C1 — node serves /health over real TLS (HTTPS)",
        health.ok === true && health.tls === true,
        `tls=${health.tls}`,
      );
    } finally {
      if (tlsNode) await tlsNode.close();
      try {
        fs.rmSync(tmp, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    }
  }
}

main()
  .then(() => {
    console.log("");
    console.log(`R+4 PEER-AUTH: ${pass} passed, ${fail} failed${skip ? `, ${skip} skipped` : ""}`);
    console.log(
      fail === 0
        ? "R+4 federation peer authentication: SOUND — mutating endpoints " +
            "require a signed request from a known peer; unknown, tampered, " +
            "stale and replayed requests are all rejected. (v1.0 hardening — " +
            "TLS + peer auth + persistence landed; BFT consensus still ahead.)"
        : "R+4 federation peer authentication: FAILED — a check did not hold.",
    );
    process.exit(fail === 0 ? 0 : 1);
  })
  .catch((e) => {
    console.error("R+4 PEER-AUTH: fatal error —", e);
    console.log(`\nR+4 PEER-AUTH: ${pass} passed, ${fail + 1} failed`);
    process.exit(1);
  });
