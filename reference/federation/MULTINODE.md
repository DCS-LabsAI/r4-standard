# R+4 Federation — Multi-Node Prototype

This document covers `node-server.ts`: the networking layer that turns the
single-process federation logic (`manifest.ts`, `sync.ts`, `cross-issuer.ts`)
into **real federation nodes** — separate OS processes that communicate over
HTTP.

> **Honesty notice.** This is the **federation multi-node prototype**. It is a
> *functional* multi-node networked prototype — real separate processes
> talking over real HTTP, validating the sync / convergence / revocation
> protocol across a network. **v1.0 hardening is in progress:** optional peer
> authentication, TLS, manifest persistence and a sync timeout have landed (see
> "What is and isn't production-ready" below); Byzantine-fault-tolerant
> consensus and deployment have not. It is **not** production-hardened and
> **not** deployed. Do not call it "production" or "v1.0 complete".

## What a node is

A federation node is an HTTP server (`node:http`, no framework) that holds one
signed federation manifest in memory and exposes:

| Method & path  | Behaviour |
|----------------|-----------|
| `GET  /manifest` | Return this node's current signed manifest. |
| `POST /manifest` | Receive a peer's manifest; verify signature + version chain; adopt **only** if it is a strictly-higher valid version that chains correctly (the `adopt()` rule from `sync.ts`). Otherwise the node keeps its current manifest. **Mutating — peer-authenticated when `auth` is configured.** |
| `POST /verify`   | Receive a cross-issuer proof object; run `verifyCrossIssuerProof` (R+4 §8.2) against the current manifest; return `{ok, reason}`. Read-only — open. |
| `GET  /peers`    | List configured peer URLs. |
| `POST /sync`     | Trigger a sync round: fetch `/manifest` from every peer and adopt the highest valid one (convergence over the network). **Mutating — peer-authenticated when `auth` is configured.** |
| `GET  /health`   | Liveness probe (prototype convenience). |

A node is started with: a federation authority key it trusts, an initial
signed manifest, a port, and a peer list.

## Running a node

### Programmatically

```ts
import { startNode } from "./federation/node-server.js";

const node = await startNode({
  node_id: "node-1",
  authorityPk,                 // hex Ed25519 federation-authority public key
  initialManifest: genesis,    // a SignedManifest
  port: 7401,
  peers: ["http://127.0.0.1:7402", "http://127.0.0.1:7403"],
  getVerifyingKey,             // optional resolver for /verify
  auth: {                      // optional — enforce peer authentication
    authorizedPeers: [{ node_id: "node-2", publicKey: peer2Pk }],
  },
  tls: { cert, key },          // optional — serve HTTPS instead of HTTP
  statePath: "./node-state",   // optional — persist adopted manifest to disk
  syncTimeoutMs: 5000,         // optional — per-peer fetch timeout in /sync
});
// ... later
await node.close();
```

### As a standalone process

```bash
# config.json: { node_id, authorityPk, initialManifest, port, peers }
npx tsx federation/node-server.ts --config config.json
```

A CLI-launched node prints `[node-server] READY <node_id>` on stdout once it
is listening. A `getVerifyingKey` resolver cannot cross a process boundary, so
a CLI node uses a null resolver — `/verify` still runs the full §8.2
federation gate (manifest signature, membership, accepted-circuit checks); the
Groth16 step then reports `vk_unavailable`, which is a correct structured
result.

## Running the multi-node test

```bash
cd r4-standard/reference
npm install            # if node_modules is absent
npx tsx federation/test/multinode.test.ts
```

The test spawns **3 real `tsx node-server.ts` processes** on ports 7401–7403,
drives them only over HTTP via `fetch`, and asserts: 3 nodes start at genesis;
a v2 update on node-1 converges to nodes 2 & 3 via `/sync`; a v3 revocation
propagates network-wide; a forged manifest and a stale manifest are rejected;
and `/verify` returns structured results. It prints
`R+4 MULTI-NODE: N passed, M failed` and kills every spawned process and temp
file on exit. Last observed run: **13 passed, 0 failed**.

## What is and isn't production-ready

**Real / sound in this prototype:**

- Real separate OS processes, each an independent HTTP server.
- Real HTTP transport — peers sync via `fetch`, never direct function calls.
- Real cryptography — Ed25519 manifest signatures, SHA-256 version-chain.
- The sync / convergence / fork-rejection / revocation protocol behaves
  correctly across the network.

**v1.0 hardening — landed (opt-in):**

- **Peer authentication** (`peer-auth.ts`) — when a node is started with an
  `auth` config, the mutating endpoints `POST /manifest` and `POST /sync`
  require an Ed25519-signed request from a listed peer. Unknown-signer,
  tampered, clock-skewed and replayed requests are all rejected. `POST /verify`
  and the GET endpoints stay open (read-only). Tested by
  `test/peer-auth.test.ts` (`npm run test:federation:auth`).
- **TLS** — when a node is started with a `tls: { cert, key }` config it
  serves HTTPS instead of plaintext HTTP.
- **Manifest persistence** (`persistence.ts`) — when a node is started with a
  `statePath`, every adopted manifest is written to disk atomically, and on
  restart the node boots from the persisted manifest (if newer and validly
  signed) instead of reverting to its initial manifest. A persisted manifest
  that fails the signature check is ignored. Tested by `test/persistence.test.ts`
  (`npm run test:federation:persistence`).
- **Sync timeout** — every peer fetch in `POST /sync` is bounded by
  `syncTimeoutMs` (default 5000) via an `AbortController`, so a hung peer is
  reported as `timeout` and can never stall a sync round.

When `auth` is omitted the node runs in legacy mode (a warning is logged) and
mutating endpoints are open, exactly as the original prototype — which is why
`multinode.test.ts` still passes unchanged.

**Still out of scope — NOT production-ready:**

- **No production-grade Byzantine fault tolerance / consensus** — the manifest
  is still minted by a single trusted authority key; adoption is the strict
  version-chain rule, nothing more.
- **No replay-ledger persistence** — the adopted manifest now survives a
  restart (`statePath`), but the peer-auth replay ledger is still in-memory, so
  replay protection resets on restart (bounded by the peer-auth timestamp
  window).
- **No retry/backoff, no partition or liveness handling, no rate limiting.**
- **Not deployed** anywhere.

Closing these gaps is the remaining work toward a production federation network.
