# R+4 — Federated Zero-Knowledge Verification Standard

[![Spec](https://img.shields.io/badge/spec-r%2B4%2Fv0.1-blue)](https://dcslabs.ai/standard/r4)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-public%20draft-orange)](https://dcslabs.ai/standard/r4)
[![Built on](https://img.shields.io/badge/built%20on-R%2B2%20%2B%20R%2B3-green)](https://github.com/DCS-LabsAI/r2-standard)

> An open specification for zero-knowledge proofs over R+2 receipts and R+3
> audit bundles — prove a compliance property holds without revealing the
> underlying receipts. Groth16 / BN254. MIT-licensed.

**🌐 Full spec:** <https://dcslabs.ai/standard/r4>
**🔗 Built on:** [R+2](https://github.com/DCS-LabsAI/r2-standard) + R+3

---

## What is R+4?

R+2 makes every agent action signable; R+3 aggregates them into Merkle-rooted
audit bundles. Both share one property: **the verifier sees the data.**

R+4 removes that. An R+4 proof is a short cryptographic object (~200 bytes on
BN254) that lets a verifier check a specific, pre-committed statement about a
set of receipts — e.g. *"≥ 10,000 receipts in this bundle were signed under
policy `pol_v3` with amount ≤ $5.00"* — **without learning anything else**:
not the receipts, not the principals, not the exact count.

Where R+2 makes every action provable and R+3 makes every period provable,
**R+4 makes every compliance claim verifiable without disclosure.**

---

## Reference circuit

The reference statement class is **`r4-threshold-count-v1`** — implemented in
`reference/circuits/threshold-count.circom`. It enforces, in-circuit:

- a SHA-256 Merkle path from each consumed receipt to the public bundle root,
- the receipt's EdDSA signature,
- the receipt timestamp inside the declared window,
- policy-ID and amount-cap bounds.

Compiled profile: **1,197,221 R1CS constraints** (64-receipt Groth16 / BN254
profile).

---

## Quick start

```bash
cd reference
npm install

# 1. compile circuit → R1CS → dev keys → Solidity verifier
npm run build

# 2. generate a real Groth16 proof from the worked example
npm run prove -- --bundle example-bundle.json \
     --statement example-statement.json --artifacts ./artifacts --out proof.json

# 3. verify it
npm run verify -- proof.json
```

Expected: the witness suite passes `7/7`, and the verifier prints
`groth16 verify : valid`.

> **Trust note.** `npm run build` produces **development proving/verifying
> keys** from a single-party setup. They are correct for testing the circuit,
> the proof pipeline, and the on-chain verifier — but they are **not**
> production-trust keys. Production keys come from a multi-party trusted-setup
> ceremony (see `reference/ceremony/`). Until that ceremony runs, every R+4
> proof in this repo is a **dev-key proof** and must be described as such.

---

## On-chain verifier — reference deployment

`build.sh` emits a Groth16 Solidity verifier (`reference/solidity/`). It was
deployed to **Base Sepolia** and its `verifyProof()` was called on-chain with
the real proof — it returned **`true`**.

| Item | Value |
|---|---|
| Network | Base Sepolia (testnet), chain ID 84532 |
| Verifier contract | [`0x91d98bc1…0553e1cd`](https://sepolia.basescan.org/address/0x91d98bc1bf053a53de173be055bf67190553e1cd) |
| Deployment tx | [`0x31e7a6b2…1617609e7`](https://sepolia.basescan.org/tx/0x31e7a6b29ebb1d58b0220fc2d4b242e18eec1ae067d73da9944edab1617609e7) |
| Block | 41,834,124 |
| Keys | development keys — testnet only |

---

## Repository structure

```
r4-standard/
├── reference/
│   ├── circuits/             # threshold-count.circom — the reference circuit
│   ├── prover/               # generate a Groth16 proof from a bundle + statement
│   ├── verifier/             # verify a proof off-chain
│   ├── solidity/             # generated Groth16 Solidity verifier
│   ├── scripts/              # deploy + on-chain verify scripts
│   ├── ceremony/             # multi-party trusted-setup coordination
│   ├── test/                 # witness + statement-logic test suite
│   ├── build.sh              # compile → R1CS → keys → Solidity verifier
│   ├── COMPILE_RUNBOOK.md    # full compile procedure (circom + snarkjs)
│   └── example-*.json        # worked bundle / statement / proof
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
└── LICENSE
```

The canonical specification text lives on the website
(<https://dcslabs.ai/standard/r4>). This repository holds the reference
circuit and proof tooling.

---

## License

The specification and reference implementation are released under the
[MIT License](LICENSE). DCS AI Technologies L.L.C holds no patents covering
R+4 and has filed none.

---

## Contact

- **Editorial:** standards@dcslabs.ai
- **Security:** security@dcslabs.ai
- **Source-of-truth spec:** <https://dcslabs.ai/standard/r4>

— DCS AI Technologies L.L.C, Dubai
