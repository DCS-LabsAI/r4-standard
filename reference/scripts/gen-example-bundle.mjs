// ============================================================================
// gen-example-bundle.mjs — generate a runnable R+4 example bundle + statement.
//
// The prover (prover/prove.ts) consumes an `R3Bundle` whose receipts carry
// real EdDSA-Poseidon signatures and depth-20 Poseidon-Merkle inclusion
// proofs. The repo previously shipped only sketch placeholders, so
// `npm run prove` had no valid input. This regenerates real, self-consistent
// example data:
//
//   example-bundle.json     5 signed receipts + a depth-20 Merkle root
//   example-statement.json  the matching R4 statement ("≥3 receipts …")
//
// All crypto is verified here before the files are written: every signature
// verifies under the issuer key, and every receipt's 20-level Merkle path
// folds back to bundle_root. The Groth16 wrap of this same data is what
// `npm run build && npm run prove` produces on a machine with circom.
//
// Test issuer key: 32 bytes of 0x11 — the same key witness-test.mjs uses.
// Published / test-only — never use it in production.
//
// Run:  node scripts/gen-example-bundle.mjs   (or: npm run gen-example)
// ============================================================================
import { buildPoseidon, buildEddsa } from "circomlibjs";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(HERE, "..");

const TREE_DEPTH = 20;          // must match circuit ThresholdCount(64, 20)
const POLICY_ID = "3";          // numeric — prove.ts hashToField() is identity
const AMOUNT_CAP = 500;         // statement cap, cents
const THRESHOLD = 3;            // statement: "≥ 3 eligible receipts"

const poseidon = await buildPoseidon();
const eddsa = await buildEddsa();
const F = poseidon.F;
const d = (x) => F.toString(x);   // field element → decimal string

// —— issuer identity (test-only key) ——————————————————————————————
const issuerSeed = Buffer.alloc(32, 0x11);
const issuerPub = eddsa.prv2pub(issuerSeed);

// —— 5 receipts: [ RFC3339 ts, amount cents, nonce ] ——————————————
const RAW = [
  ["2026-01-15T10:00:00Z", 120, 1001],
  ["2026-01-31T12:00:00Z", 450, 1002],
  ["2026-02-14T09:30:00Z", 300, 1003],
  ["2026-03-01T00:00:00Z", 480, 1004],
  ["2026-03-20T18:45:00Z",  95, 1005],
];

// leaf / receipt_hash = Poseidon([ ts_unix, policy, amount, nonce ])
const receipts = RAW.map(([ts, amount, nonce]) => {
  const tsUnix = Math.floor(Date.parse(ts) / 1000);
  const hash = poseidon([tsUnix, Number(POLICY_ID), amount, nonce]);
  const sig = eddsa.signPoseidon(issuerSeed, hash);
  return { ts, tsUnix, amount, nonce, hash, sig };
});

// —— depth-20 sparse Poseidon-Merkle tree ————————————————————————
// zeros[L] = root of an all-zero subtree of height L.
const zeros = [F.e(0)];
for (let L = 1; L <= TREE_DEPTH; L++) zeros[L] = poseidon([zeros[L - 1], zeros[L - 1]]);

const memo = new Map();
function node(L, idx) {
  // Any subtree entirely right of the 5 populated leaves is all-zero.
  if (idx > (4 >> L)) return zeros[L];
  const key = `${L}:${idx}`;
  if (memo.has(key)) return memo.get(key);
  let v;
  if (L === 0) v = idx < receipts.length ? receipts[idx].hash : F.e(0);
  else v = poseidon([node(L - 1, 2 * idx), node(L - 1, 2 * idx + 1)]);
  memo.set(key, v);
  return v;
}
const root = node(TREE_DEPTH, 0);

// inclusion path for leaf i: sibling node + side bit at each of 20 levels
function pathFor(i) {
  const path = [], indices = [];
  for (let L = 0; L < TREE_DEPTH; L++) {
    indices.push((i >> L) & 1);                 // 0 = i is left child, 1 = right
    path.push(node(L, (i >> L) ^ 1));            // the sibling
  }
  return { path, indices };
}

// —— self-verification (the part provable without circom) —————————
let ok = 0, bad = 0;
const ck = (n, c) => { console.log(`  ${c ? "[ ok ]" : "[FAIL]"}  ${n}`); c ? ok++ : bad++; };
console.log("\nR+4 example bundle — self-verification\n");

for (let i = 0; i < receipts.length; i++) {
  const r = receipts[i];
  ck(`receipt ${i}: EdDSA-Poseidon signature verifies under issuer key`,
    eddsa.verifyPoseidon(r.hash, r.sig, issuerPub));

  // fold the inclusion path the way the circuit's MerkleProof does
  const { path, indices } = pathFor(i);
  let acc = r.hash;
  for (let L = 0; L < TREE_DEPTH; L++) {
    acc = indices[L] === 0 ? poseidon([acc, path[L]]) : poseidon([path[L], acc]);
  }
  ck(`receipt ${i}: depth-20 Merkle path folds to bundle_root`, F.eq(acc, root));
}

// —— emit the files ——————————————————————————————————————————————
const bundle = {
  bundle_root: d(root),
  issuer_id: "did:dcs:r4-test-issuer",
  issuer_pk: [d(issuerPub[0]), d(issuerPub[1])],
  receipts: receipts.map((r, i) => {
    const { path, indices } = pathFor(i);
    return {
      hash: d(r.hash),
      ts: r.ts,
      policy_id: POLICY_ID,
      amount_usd_cents: r.amount,
      nonce: String(r.nonce),
      signature: { R: [d(r.sig.R8[0]), d(r.sig.R8[1])], S: r.sig.S.toString() },
      merkle_path: { path: path.map(d), indices },
    };
  }),
};

const statement = {
  circuit_id: "r4-threshold-count-v1",
  bundle_root: d(root),
  period_start: "2026-01-01T00:00:00Z",
  period_end: "2026-03-31T23:59:59Z",
  threshold: THRESHOLD,
  policy_id: POLICY_ID,
  amount_cap_usd_cents: AMOUNT_CAP,
  issuer_id: "did:dcs:r4-test-issuer",
};

if (bad > 0) {
  console.log(`\n${ok}/${ok + bad} checks passed — NOT writing files (crypto inconsistent).`);
  process.exit(1);
}

writeFileSync(resolve(OUT, "example-bundle.json"), JSON.stringify(bundle, null, 2) + "\n");
writeFileSync(resolve(OUT, "example-statement.json"), JSON.stringify(statement, null, 2) + "\n");

console.log(`\n${ok}/${ok + bad} checks passed`);
console.log(`  bundle_root : ${d(root).slice(0, 24)}…`);
console.log(`  wrote example-bundle.json   (5 signed receipts, depth-${TREE_DEPTH} paths)`);
console.log(`  wrote example-statement.json  ("≥${THRESHOLD} receipts, policy ${POLICY_ID}, ≤$${AMOUNT_CAP / 100}")`);
