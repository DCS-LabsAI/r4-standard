// R+4 adversarial PROOF-level test suite.
//
// witness-test.mjs already covers the STATEMENT layer (Poseidon Merkle +
// EdDSA forgery/tamper rejection). This suite COMPLEMENTS it at the GROTH16
// PROOF layer: it loads a REAL valid proof + verifying key, confirms the
// genuine proof verifies TRUE, then applies five distinct attacks and
// asserts each one is correctly REJECTED.
//
// It calls snarkjs `groth16.verify(vKey, publicSignals, proof)` directly —
// the exact call verifier/verify.ts §7 makes.
//
// Run: node test/adversarial-proof.test.mjs

import { groth16 } from "snarkjs";
import { readFile } from "fs/promises";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");

// ── load real artifacts ───────────────────────────────────────────────
const VK = JSON.parse(await readFile(join(ROOT, "artifacts/verification_key.json"), "utf-8"));
const PROOF_OBJ = JSON.parse(await readFile(join(ROOT, "proof.json"), "utf-8"));

const GENUINE_PROOF = PROOF_OBJ.proof;             // { pi_a, pi_b, pi_c }
const GENUINE_SIGNALS = PROOF_OBJ.public_inputs;   // string[] (nPublic = 8)

const clone = (x) => JSON.parse(JSON.stringify(x));

console.log("R+4 — adversarial proof-level test (real Groth16 / BN254)\n");

let pass = 0, fail = 0;
const check = (name, ok) => {
  console.log(`  ${ok ? "[ ok ]" : "[FAIL]"}  ${name}`);
  ok ? pass++ : fail++;
};

// A safe wrapper: groth16.verify must NEVER crash the process. Malformed
// input should yield `false` or a caught Error — both count as a clean
// rejection.
async function safeVerify(vk, signals, proof) {
  try {
    const ok = await groth16.verify(vk, signals, proof);
    return { ok, threw: false };
  } catch (e) {
    return { ok: false, threw: true, err: e?.message ?? String(e) };
  }
}

// ── baseline: the genuine proof MUST verify true ───────────────────────
const baseline = await safeVerify(VK, GENUINE_SIGNALS, GENUINE_PROOF);
check("genuine proof verifies TRUE against its real verifying key",
  baseline.ok === true && baseline.threw === false);

if (!baseline.ok) {
  console.log("\n  ABORT: genuine proof did not verify — cannot run adversarial");
  console.log("         cases against an invalid baseline.\n");
  console.log(`R+4 ADVERSARIAL: ${pass} passed, ${fail + 5} failed`);
  process.exit(1);
}

// ── Attack 1: mutated proof — alter one field element in pi_a ──────────
{
  const mutated = clone(GENUINE_PROOF);
  // Flip pi_a[0] to a different valid-looking field element. A single
  // changed coordinate breaks the pairing check.
  const orig = BigInt(mutated.pi_a[0]);
  mutated.pi_a[0] = (orig === 1n ? 2n : orig - 1n).toString();
  const r = await safeVerify(VK, GENUINE_SIGNALS, mutated);
  check("ATTACK 1 — mutated pi_a element is rejected (verify = false)",
    r.ok === false);
}

// ── Attack 2: tampered public inputs — change one public signal ────────
{
  const tampered = clone(GENUINE_SIGNALS);
  // Bump the threshold signal (index 3) — claims a stronger statement
  // than the proof actually attests. Pairing must fail.
  tampered[3] = (BigInt(tampered[3]) + 1n).toString();
  const r = await safeVerify(VK, tampered, GENUINE_PROOF);
  check("ATTACK 2 — tampered public signal is rejected (verify = false)",
    r.ok === false);
}

// ── Attack 3: malformed proof — drop a required field ──────────────────
// Must produce a clean rejection (false OR caught Error), never a crash.
{
  const broken = clone(GENUINE_PROOF);
  delete broken.pi_c;                       // required curve point removed
  const r = await safeVerify(VK, GENUINE_SIGNALS, broken);
  check("ATTACK 3a — proof with missing pi_c is cleanly rejected (no crash)",
    r.ok === false);

  const corrupt = clone(GENUINE_PROOF);
  corrupt.pi_b = "not-an-array";            // structurally garbage point
  const r2 = await safeVerify(VK, GENUINE_SIGNALS, corrupt);
  check("ATTACK 3b — proof with corrupt pi_b is cleanly rejected (no crash)",
    r2.ok === false);

  const r3 = await safeVerify(VK, GENUINE_SIGNALS, null);   // null proof
  check("ATTACK 3c — null proof is cleanly rejected (no crash)",
    r3.ok === false);
}

// ── Attack 4: wrong verifying key — verify against a zeroed / foreign vk ─
{
  // 4a — a zeroed verifying key (all IC + curve points blanked).
  const zeroVk = clone(VK);
  zeroVk.IC = zeroVk.IC.map((pt) => pt.map(() => "0"));
  zeroVk.vk_alpha_1 = zeroVk.vk_alpha_1.map(() => "0");
  const r = await safeVerify(zeroVk, GENUINE_SIGNALS, GENUINE_PROOF);
  check("ATTACK 4a — proof against a zeroed verifying key is rejected",
    r.ok === false);

  // 4b — a structurally valid but DIFFERENT vk (delta_2 negated): a real
  // verifying key for a different circuit / different ceremony output.
  const foreignVk = clone(VK);
  const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
  foreignVk.vk_delta_2[0][0] =
    ((P - BigInt(foreignVk.vk_delta_2[0][0])) % P).toString();
  const r2 = await safeVerify(foreignVk, GENUINE_SIGNALS, GENUINE_PROOF);
  check("ATTACK 4b — proof against a foreign (altered) verifying key is rejected",
    r2.ok === false);
}

// ── Attack 5: swapped statement — proof for A does not verify as B ─────
// The genuine proof attests statement A. Build statement B's public
// signals (different bundle_root + period) and confirm A's proof is
// rejected as proof of B. Mirrors verify.ts §4: public inputs are derived
// from the statement, so a different statement => different signals.
{
  const signalsA = clone(GENUINE_SIGNALS);
  const signalsB = clone(GENUINE_SIGNALS);
  // statement B: different bundle_root (sig 0) and period_end (sig 2).
  signalsB[0] = (BigInt(signalsB[0]) ^ 0xdeadbeefn).toString();
  signalsB[2] = (BigInt(signalsB[2]) + 86400n).toString();

  const differ = signalsA.some((v, i) => v !== signalsB[i]);
  const rB = await safeVerify(VK, signalsB, GENUINE_PROOF);
  check("ATTACK 5 — proof for statement A does not verify as statement B",
    differ === true && rB.ok === false);
}

// ── post-check: the genuine proof STILL verifies (no state corruption) ─
{
  const r = await safeVerify(VK, GENUINE_SIGNALS, GENUINE_PROOF);
  check("post-check — genuine proof still verifies TRUE after all attacks",
    r.ok === true);
}

console.log("");
console.log(`R+4 ADVERSARIAL: ${pass} passed, ${fail} failed`);
console.log(fail === 0
  ? "R+4 proof layer: SOUND — genuine proof verifies, all forgeries/tampers rejected."
  : "R+4 proof layer: FAILED — an invalid proof was accepted or the genuine proof broke.");
process.exit(fail === 0 ? 0 : 1);
