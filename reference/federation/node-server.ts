// ===========================================================================
// R+4 "Federation Protocol" — multi-node networking layer (node-server.ts)
// R+4 spec §8 (Multi-Issuer Federated Zero-Knowledge Verification)
// ===========================================================================
//
// HONESTY NOTICE — READ THIS
// --------------------------
// This is the R+4 FEDERATION MULTI-NODE PROTOTYPE. It is a FUNCTIONAL
// multi-node networked prototype: real separate OS processes, each an
// independent HTTP(S) server, communicating over real HTTP via fetch. It
// takes the federation logic (manifest.ts / sync.ts / cross-issuer.ts) and
// runs it across a network, validating the sync / convergence / revocation
// protocol over the wire.
//
// v1.0 HARDENING — IN PROGRESS. Two production-hardening pieces are now
// available, both opt-in via NodeServerConfig:
//   - PEER AUTHENTICATION (config.auth) — when set, the mutating endpoints
//     POST /manifest and POST /sync require an Ed25519-signed request from a
//     listed peer (see peer-auth.ts). When unset, the node runs in legacy
//     mode with a warning, exactly as the original prototype did.
//   - TLS (config.tls) — when set, the node serves HTTPS instead of plaintext
//     HTTP.
//
// STILL OUT OF SCOPE (remaining v1.0 work):
//   - production-grade Byzantine-fault-tolerant consensus — the manifest is
//     still minted by a single trusted authority key
//   - persistence — no on-disk state; the replay ledger is in-memory and does
//     not survive a restart
//   - retry/backoff, partition handling, rate limiting
//   - it is NOT deployed anywhere
//
// Do not call this "production" or "v1.0 complete". See federation/MULTINODE.md.
// ===========================================================================

import * as http from "node:http";
import * as https from "node:https";
import { sha512 } from "@noble/hashes/sha2.js";
import * as ed from "@noble/ed25519";

import {
  verifyManifest,
  type SignedManifest,
} from "./manifest.js";
import {
  makeNode,
  adopt,
  type FederationNode,
} from "./sync.js";
import {
  verifyCrossIssuerProof,
  type R4ProofObject,
  type GetVerifyingKey,
} from "./cross-issuer.js";
import {
  verifyRequest,
  ReplayLedger,
  type PeerAuthConfig,
} from "./peer-auth.js";

// @noble/ed25519 v3 needs sha512 wired in for sync APIs.
ed.hashes.sha512 = (...m) => sha512(ed.etc.concatBytes(...m));

// ── node configuration ──────────────────────────────────────────────────────

export interface NodeServerConfig {
  node_id: string;
  /** Federation-authority public key this node trusts (hex). */
  authorityPk: string;
  /** The initial signed manifest this node boots with. */
  initialManifest: SignedManifest;
  /** TCP port to listen on. */
  port: number;
  /** Base URLs of peer nodes, e.g. ["http://127.0.0.1:7002"]. */
  peers: string[];
  /**
   * Optional verifying-key resolver for /verify. In this prototype the resolver
   * is process-local; a real deployment would fetch vks from a registry.
   */
  getVerifyingKey?: GetVerifyingKey;
  /**
   * Optional peer authentication. When present, the mutating endpoints
   * (POST /manifest, POST /sync) require an Ed25519-signed request from a
   * listed peer. When absent the node runs in legacy/prototype mode (a
   * warning is logged) and accepts unauthenticated mutating requests.
   */
  auth?: PeerAuthConfig;
  /**
   * Optional TLS. When present the node serves HTTPS instead of plaintext
   * HTTP. `cert` and `key` are PEM strings.
   */
  tls?: { cert: string; key: string };
}

export interface RunningNode {
  server: http.Server | https.Server;
  /** The in-memory FederationNode (its `.current` is the live manifest). */
  fed: FederationNode;
  config: NodeServerConfig;
  /** Stop the server and free the port. */
  close: () => Promise<void>;
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

// ── server ───────────────────────────────────────────────────────────────────

/**
 * Start one federation node as a real HTTP(S) server.
 *
 * The node exposes:
 *   GET  /manifest  — this node's current signed manifest (open)
 *   POST /manifest  — receive a peer's manifest; verify sig + version chain;
 *                     adopt iff strictly-higher valid version (sync.ts rule).
 *                     MUTATING — peer-authenticated when config.auth is set.
 *   POST /verify    — receive a cross-issuer proof; run verifyCrossIssuerProof
 *                     against the current manifest (open — read-only)
 *   GET  /peers     — list configured peer URLs (open)
 *   POST /sync      — fetch /manifest from every peer, adopt the highest valid.
 *                     MUTATING — peer-authenticated when config.auth is set.
 *   GET  /health    — liveness probe; reports auth/tls mode (open)
 */
export function startNode(config: NodeServerConfig): Promise<RunningNode> {
  const fed: FederationNode = makeNode(
    config.node_id,
    config.authorityPk,
    config.initialManifest,
  );

  const getVk: GetVerifyingKey = config.getVerifyingKey ?? (() => null);

  // Per-node replay ledger for peer-authenticated requests.
  const replayLedger = new ReplayLedger();
  if (!config.auth) {
    console.warn(
      `[node-server] ${config.node_id}: peer authentication DISABLED ` +
        `(no config.auth) — legacy/prototype mode; mutating endpoints are open.`,
    );
  }

  /**
   * Gate a mutating request. Returns null when the request is allowed, or a
   * rejection reason. In legacy mode (no config.auth) every request is allowed.
   */
  function gate(
    method: string,
    path: string,
    raw: string,
    headers: http.IncomingHttpHeaders,
  ): { reason: string } | null {
    if (!config.auth) return null; // legacy/prototype mode
    const r = verifyRequest(method, path, raw, headers, config.auth, replayLedger);
    return r.ok ? null : { reason: r.reason };
  }

  const handler = async (
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> => {
    const method = req.method ?? "GET";
    const url = (req.url ?? "/").split("?")[0];
    // Read the body once for any POST, so it is available both to the auth
    // check (which signs over the body) and to the route logic.
    const raw = method === "POST" ? await readBody(req) : "";

    try {
      // ── GET /manifest ───────────────────────────────────────────────────
      if (method === "GET" && url === "/manifest") {
        return sendJson(res, 200, fed.current);
      }

      // ── GET /peers ──────────────────────────────────────────────────────
      if (method === "GET" && url === "/peers") {
        return sendJson(res, 200, { node_id: fed.node_id, peers: config.peers });
      }

      // ── GET /health ─────────────────────────────────────────────────────
      if (method === "GET" && url === "/health") {
        return sendJson(res, 200, {
          node_id: fed.node_id,
          version: fed.current.version,
          auth: config.auth ? "enforced" : "legacy",
          tls: config.tls ? true : false,
          ok: true,
        });
      }

      // ── POST /manifest  (MUTATING — peer-authenticated) ─────────────────
      // Receive a manifest from a peer. Verify signature + version chain via
      // adopt() (the sync.ts rule): adopt ONLY a strictly-higher valid
      // version that chains correctly. Otherwise keep the current manifest.
      if (method === "POST" && url === "/manifest") {
        const denied = gate(method, url, raw, req.headers);
        if (denied) {
          return sendJson(res, 401, { adopted: false, reason: denied.reason });
        }
        let candidate: SignedManifest;
        try {
          candidate = JSON.parse(raw);
        } catch {
          return sendJson(res, 400, { adopted: false, reason: "malformed_json" });
        }
        const before = fed.current.version;
        const decision = adopt(fed, candidate);
        return sendJson(res, decision.adopted ? 200 : 409, {
          adopted: decision.adopted,
          reason: decision.reason,
          fromVersion: before,
          version: fed.current.version,
        });
      }

      // ── POST /verify  (read-only — NOT authenticated) ───────────────────
      // Run §8.2 cross-issuer verification against the CURRENT manifest.
      // Verification is non-mutating and discloses nothing, so it is open.
      if (method === "POST" && url === "/verify") {
        let proof: R4ProofObject;
        try {
          proof = JSON.parse(raw);
        } catch {
          return sendJson(res, 400, { ok: false, reason: "malformed_json" });
        }
        const result = await verifyCrossIssuerProof(
          proof,
          fed.current,
          getVk,
          fed.authorityPk,
        );
        return sendJson(res, 200, {
          ok: result.ok,
          reason: result.reason,
          checkedAgainstVersion: fed.current.version,
        });
      }

      // ── POST /sync  (MUTATING — peer-authenticated) ─────────────────────
      // Trigger a sync round: fetch /manifest from every peer, then adopt the
      // highest valid one. Convergence over the real network.
      if (method === "POST" && url === "/sync") {
        const denied = gate(method, url, raw, req.headers);
        if (denied) {
          return sendJson(res, 401, { adopted: false, reason: denied.reason });
        }
        const fetched: { peer: string; version?: number; error?: string }[] = [];
        const candidates: SignedManifest[] = [];

        for (const peer of config.peers) {
          try {
            const r = await fetch(peer.replace(/\/$/, "") + "/manifest");
            if (!r.ok) {
              fetched.push({ peer, error: `http_${r.status}` });
              continue;
            }
            const m = (await r.json()) as SignedManifest;
            fetched.push({ peer, version: m?.version });
            candidates.push(m);
          } catch (e) {
            fetched.push({
              peer,
              error: e instanceof Error ? e.message : String(e),
            });
          }
        }

        // sort candidates by version descending; try to adopt the highest
        // valid one. adopt() rejects anything that is not a strictly-higher,
        // correctly-chained, authority-signed +1 successor.
        candidates.sort((a, b) => (b?.version ?? 0) - (a?.version ?? 0));
        const before = fed.current.version;
        let adopted = false;
        let reason = "no_newer_valid_manifest";
        for (const cand of candidates) {
          // skip structurally-broken candidates early.
          if (verifyManifest(cand, fed.authorityPk).ok === false) continue;
          const d = adopt(fed, cand);
          if (d.adopted) {
            adopted = true;
            reason = d.reason;
            break;
          }
          reason = d.reason;
        }
        return sendJson(res, 200, {
          node_id: fed.node_id,
          peersContacted: fetched,
          adopted,
          reason,
          fromVersion: before,
          version: fed.current.version,
        });
      }

      // ── unknown route ───────────────────────────────────────────────────
      return sendJson(res, 404, { error: "not_found", method, url });
    } catch (e) {
      return sendJson(res, 500, {
        error: "internal",
        detail: e instanceof Error ? e.message : String(e),
      });
    }
  };

  const server: http.Server | https.Server = config.tls
    ? https.createServer(
        { cert: config.tls.cert, key: config.tls.key },
        handler,
      )
    : http.createServer(handler);

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve({
        server,
        fed,
        config,
        close: () =>
          new Promise<void>((res2) => server.close(() => res2())),
      });
    });
  });
}

// ── CLI entrypoint ───────────────────────────────────────────────────────────
//
// Run as a standalone process:
//   tsx federation/node-server.ts --config <path-to-json>
//
// The config JSON must contain { node_id, authorityPk, initialManifest,
// port, peers }, and may contain { auth, tls }. (getVerifyingKey cannot cross
// a process boundary, so a CLI-launched node uses a null resolver — /verify
// still runs the §8.2 federation gate; the Groth16 step then reports
// vk_unavailable, which is a correct structured result.)

async function cliMain(): Promise<void> {
  const args = process.argv.slice(2);
  const idx = args.indexOf("--config");
  if (idx === -1 || !args[idx + 1]) {
    console.error("usage: tsx node-server.ts --config <config.json>");
    process.exit(2);
  }
  const fs = await import("node:fs");
  const cfg = JSON.parse(fs.readFileSync(args[idx + 1], "utf8")) as NodeServerConfig;
  const node = await startNode(cfg);
  console.log(
    `[node-server] ${cfg.node_id} listening on ` +
      `${cfg.tls ? "https" : "http"}://127.0.0.1:${cfg.port} ` +
      `(v${node.fed.current.version}, ${cfg.peers.length} peers, ` +
      `auth=${cfg.auth ? "enforced" : "legacy"})`,
  );
  // signal readiness to a parent process watching stdout.
  console.log(`[node-server] READY ${cfg.node_id}`);

  const shutdown = () => {
    node.close().then(() => process.exit(0));
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

// Run the CLI only when this file is the process entrypoint.
const isEntrypoint =
  typeof process !== "undefined" &&
  process.argv[1] !== undefined &&
  /node-server\.ts$/.test(process.argv[1]);

if (isEntrypoint) {
  cliMain().catch((e) => {
    console.error("[node-server] fatal:", e);
    process.exit(1);
  });
}
