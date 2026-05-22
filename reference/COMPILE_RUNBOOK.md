# R+4 Compile Runbook — circom + one real Groth16 proof

This is the executable procedure to take R+4 from "code-complete" to "a real
Groth16 proof generated and verified." It needs the **circom toolchain**,
which is a Rust binary and cannot run in the DCS build sandbox — so this is a
runbook for your build machine.

Everything else is done: the circuit, `build.sh`, the prover, the verifier,
the Solidity verifier, and the ceremony tooling are all written. The
statement logic is proven — `test/witness-test.mjs` runs **7/7** against the
real Poseidon + EdDSA primitives (you can run it now: `cd test && npm i &&
node witness-test.mjs`). What remains is compiling the circuit and wrapping
that proven computation in a SNARK.

Estimated time: ~10 minutes (most of it the one-time circom install).

---

## 1 · Install the toolchain (one-time)

**circom** (the Rust ZK compiler — `pragma circom 2.1.6` needs circom 2.x,
*not* the deprecated npm `circom` 0.5):

```bash
# Option A — prebuilt binary (fastest)
#   download the circom binary for your OS from
#   https://github.com/iden3/circom/releases  (latest 2.x),
#   chmod +x it, and put it on your PATH.

# Option B — build from source
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/iden3/circom.git && cd circom
cargo build --release
cargo install --path circom
```

**snarkjs + the repo's own deps:**

```bash
npm install -g snarkjs
cd dcslabs-site/standard/r4-reference
npm install            # snarkjs, circomlib, circomlibjs, tsx — declared in package.json
```

Verify:

```bash
circom --version     # expect 2.1.x or newer
snarkjs --version
```

---

## 2 · Compile the circuit + dev keys

```bash
cd dcslabs-site/standard/r4-reference
./build.sh dev
```

`build.sh` runs five steps: circom compile → R1CS, Phase-1 Powers of Tau
(dev), Phase-2 Groth16 setup, export verifying key, export Solidity verifier.

Expected `artifacts/` after a successful run:

```
threshold-count.r1cs                 the rank-1 constraint system
threshold-count_js/threshold-count.wasm   circom's witness generator
threshold_count.wasm                 flat copy the prover loads
threshold_count_final.zkey           the proving key
verification_key.json                the verifying key (public)
```

> Fix applied this session: `build.sh` step 1 now copies the wasm out of
> circom's hyphenated `threshold-count_js/` directory to the flat
> `threshold_count.wasm` path the prover expects. Without that copy the
> prover fails with "wasm not found" on first run.

The `snarkjs r1cs info` line prints the constraint count — record it; it
should be on the order of tens of thousands of constraints for the 64-receipt
profile (EdDSA + Poseidon-Merkle dominate the cost).

---

## 3 · Generate one real Groth16 proof

`example-bundle.json` + `example-statement.json` ship in the repo — real,
self-consistent data (5 signed receipts, a depth-20 Poseidon-Merkle root).
Regenerate them anytime with `npm run gen-example`.

```bash
npm run prove -- \
  --bundle example-bundle.json \
  --statement example-statement.json \
  --artifacts ./artifacts \
  --out ./proof.json
```

`npm run prove` runs `tsx prover/prove.ts`. It builds the witness from the
R+3 bundle, runs `groth16.fullProve`, and writes `proof.json`.

---

## 4 · Verify the proof

```bash
npm run verify -- ./proof.json
```

Expect `[ ok ] groth16 verify : valid (<10 ms)`. That is the end-to-end
SNARK — a real proof, generated and verified.

Optionally confirm the on-chain path compiles:

```bash
# artifacts/.../Groth16Verifier.gen.sol was emitted by build.sh step 5
forge build   # or solc — just confirm the generated verifier compiles
```

---

## 5 · What this closes (R+4 test plan)

| Test | Step | Pass criterion |
|------|------|----------------|
| Statement / constraint logic | `test/witness-test.mjs` | 7/7 (already green) |
| Circuit compile + witness | step 2 | `artifacts/` populated, R1CS info prints |
| Real proof generate | step 3 | `proof.json` written |
| Real proof verify | step 4 | `groth16 verify : valid` |
| Trusted-setup ceremony | `ceremony/CEREMONY.md` | separate ≥14-day milestone (Q3 2026) |

After step 4, record the constraint count and proof timing in the roadmap and
flip R+4's "circuit compile" item to done.

---

## Important — dev keys vs production

`./build.sh dev` produces **single-contributor development keys**. Whoever ran
the build knows the Groth16 "toxic waste" and could forge proofs. That is fine
for testing and the reference verifier — **not** for production trust.

Production keys require the multi-party trusted-setup ceremony
(`ceremony/CEREMONY.md`: ≥5 independent contributors over ≥14 days). That is a
coordinated human event the cryptography requires; it is not code and cannot
be compressed. After the ceremony, `./build.sh prod` consumes the ceremony
output. Until then, do not present dev-key proofs as production-trustless.

---

## Troubleshooting

- **`circom: command not found`** — you installed the npm `circom` (0.5.x).
  Remove it; install circom 2.x per step 1.
- **`include "circomlib/..." not found`** — run `npm install circomlib` in
  `r4-reference/`; `build.sh` passes `-l node_modules` so it resolves there.
- **`wasm not found` in the prover** — you have an old `build.sh` without the
  flatten step; re-pull, or copy `artifacts/threshold-count_js/threshold-count.wasm`
  to `artifacts/threshold_count.wasm` manually.
- **Phase-1 ptau too small** — the dev build uses power 16. If circom reports
  more constraints than `2^16` supports, raise the power in `build.sh` step 2.
