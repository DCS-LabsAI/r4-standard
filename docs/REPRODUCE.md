# DCS Labs R-Series — Reproducibility Pack

This guide lets an independent reviewer re-verify the R+2, R+3, and R+4
reference implementations with minimal steps. It addresses the
"reproducibility" gap raised in technical review: every claim below maps to a
command you can run and an expected output you can check.

**Honest scope note up front:**

- This is **not** a one-command full reproduction. Each reference repo has its
  own dependency tree and needs its own `npm install`.
- The R+2 adversarial suite intentionally reports **1 documented gap**
  (nonce-uniqueness). 9 pass + 1 known gap is the *expected* result, not a
  failure.
- R+4's witness and proof tests run against **development keys**. Verifying a
  proof against the **production proving/verifying keys** additionally requires
  the trusted-setup ceremony artifacts (`pot22_final.ptau`,
  `phase2_final.zkey`), which are included under `r4-reference/ceremony/`.
- On-chain items are verified by opening public block-explorer links in a
  browser — no key material or network credentials are needed for that.

---

## 0. Prerequisites

Install these once. Versions shown are the minimums the repos were built with.

| Tool | Minimum | Check | Notes |
|---|---|---|---|
| Node.js | LTS (>= 18) | `node --version` | R+2 `engines` requires `>=18`. |
| npm | bundled with Node | `npm --version` | Used for `npm install` / `npm test` in each repo. |
| tsx | via `npx` | `npx tsx --version` | TypeScript runner; R+3 and R+4 ship it as a devDependency, so `npm install` in those repos provides it. |
| snarkjs | >= 0.7 | `npx snarkjs --help` | R+4 ships it as a dependency; `npm install` in `r4-reference` provides it. Needed only for the ceremony verify step. |

A normal internet connection is needed for the `npm install` steps and for
opening block-explorer links. The off-chain test steps themselves do not need
network access once dependencies are installed.

Throughout this guide, `<repo-root>` is the directory that contains
`rseries-hardening/`, `r2-standard-repo/`, `r3-standard/`, and `dcslabs-site/`.

---

## 1. Verify R+2 — Open Provenance Standard

Repo path: `r2-standard-repo/verifier/`

```bash
cd <repo-root>/r2-standard-repo/verifier
npm install
```

### 1.1 Unit tests

```bash
npm test          # runs: node test/verify.test.js
```

Expected: all unit assertions pass, process exits 0.

### 1.2 Conformance suite (10 vectors)

```bash
npm run conformance   # runs: node bin/r2-verify.js --test-vectors ../spec/test-vectors
```

Expected: the 10-vector conformance suite reports **10/10 vectors pass**.

### 1.3 Scale test (10k receipts)

```bash
npm run scale         # runs: node test/scale.test.js
```

Expected: a batch of 10,000 receipts is verified successfully with a printed
throughput figure; process exits 0.

### 1.4 Adversarial suite

```bash
node test/adversarial.test.js
```

Expected: **9 passed + 1 documented gap**. The single non-pass is the known,
documented **nonce-uniqueness** gap — the R+2 verifier checks signatures and
canonicalization but does not by itself enforce cross-receipt nonce uniqueness.
This is expected and is not a regression. A run that shows "10 passed" or that
hides the gap would itself be wrong.

---

## 2. Verify R+3 — Tamper-Evident Audit Export

Repo path: `r3-standard/reference/`

```bash
cd <repo-root>/r3-standard/reference
npm install
```

### 2.1 Regression suite

```bash
npm test          # runs: tsx test/r3-regression.ts
```

Expected: **10/10 regression checks pass**, process exits 0.

### 2.2 Adversarial suite

```bash
npx tsx test/adversarial.test.ts
```

Expected: **6/6 adversarial checks pass**, process exits 0.

---

## 3. Verify R+4 — Federated Zero-Knowledge Verification

Repo path: `dcslabs-site/standard/r4-reference/`

```bash
cd <repo-root>/dcslabs-site/standard/r4-reference
npm install
```

### 3.1 Witness tests

```bash
npm test          # runs: node test/witness-test.mjs
```

Expected: **7/7 witness tests pass**, process exits 0.

### 3.2 Proof adversarial suite

```bash
node test/adversarial-proof.test.mjs
```

Expected: **10/10 proof adversarial checks pass**, process exits 0.

### 3.3 Ceremony verification (production keys)

This step proves the production proving/verifying keys came from a valid
trusted-setup ceremony. It needs the ceremony artifacts shipped in the repo:
`ceremony/pot22_final.ptau`, `ceremony/phase2_final.zkey`, and
`artifacts/threshold-count.r1cs`.

```bash
cd <repo-root>/dcslabs-site/standard/r4-reference/ceremony
npx snarkjs zkey verify ../artifacts/threshold-count.r1cs pot22_final.ptau phase2_final.zkey
```

Expected final line: **`ZKey Ok!`**

snarkjs also re-prints the contribution chain (5 contributors + 1 beacon),
which should match the published ceremony transcript
(`r4-standard/reference/ceremony/CEREMONY_TRANSCRIPT.md`).

**Honest scope:** the R+4 v0.1 ceremony had 5 contributors (family + DCS Labs
internal staff). The keys are valid and the chain verifies, but the 1-of-N
independence guarantee is only as strong as the contributors' independence. A
broader ceremony with fully independent external contributors is the
recommended follow-up.

---

## 4. Verify on-chain items

These are verified by opening the links below in any browser. No credentials or
local tooling required. The transaction calldata / Merkle root should match the
roots in the corresponding anchored bundle files.

### 4.1 R+3 anchors

R+3 bundles are anchored on **both** Base Sepolia (testnet) and Base mainnet.
Both anchor the same Merkle root
`0xe7da8052d2151a7187ff8f7757d2e993b1a963cb70d20d10085df4d7a2896273`
(bundle `r3_2026-05_1`).

| Network | Chain ID | Transaction | Block | Bundle file |
|---|---|---|---|---|
| Base Sepolia (testnet) | 84532 | <https://sepolia.basescan.org/tx/0x8ef5e38531e5d4a1a13c18df952f560941b30371b6c3053ada2cc85392746533> | 41,814,917 | `r3-standard/reference/bundle-anchored.json` |
| Base mainnet | 8453 | <https://basescan.org/tx/0xab89f1bd74484b0826e06542b9b5babaf1a720261616abd99584c9471c7fc26e> | 46,304,888 | `r3-standard/reference/bundle-anchored-mainnet.json` |

To check: open each link, confirm the transaction is confirmed, and confirm its
input data / calldata contains the Merkle root above.

### 4.2 R+4 verifiers

The R+4 Groth16 Solidity verifier was deployed on both networks. The testnet
deployment used the **dev** proving key; the mainnet deployment used the
**production** key from the v0.1 ceremony (Section 3.3).

| Network | Verifier contract | Deployment tx |
|---|---|---|
| Base Sepolia (testnet, dev key) | <https://sepolia.basescan.org/address/0x91d98bc1bf053a53de173be055bf67190553e1cd> | <https://sepolia.basescan.org/tx/0x31e7a6b29ebb1d58b0220fc2d4b242e18eec1ae067d73da9944edab1617609e7> |
| Base mainnet (production key) | <https://basescan.org/address/0xabf8626c20e6bf21a9fdcd4e9f80c17ac8963209> | <https://basescan.org/tx/0x9df6edff61e9c63f25fbb1247a77a0f74cea128bb5a99427ea4bea902f01f53f> (block 46,343,838) |

To check: open each address link and confirm the contract exists and is the
Groth16 verifier; open each deploy-tx link and confirm it is confirmed.

### 4.3 Bitcoin beacon — block 950552

The R+4 v0.1 ceremony was finalized with a public random beacon: the hash of
Bitcoin block **950552** (mined 2026-05-23 00:15:21).

- Block hash: `000000000000000000014bbb2806609a12f65d4628e8f45df2a4a51d58cca687`
- Verify: <https://mempool.space/block/000000000000000000014bbb2806609a12f65d4628e8f45df2a4a51d58cca687>

To check: open the link, confirm the block height is 950552 and the hash
matches. The beacon being a *future* block at ceremony time is what makes the
final contribution unpredictable and unforgeable.

---

## 5. One-step off-chain helper

`reproduce.sh` (in this directory) runs the **off-chain R+2 and R+3 checks** in
sequence and prints a pass/fail summary. It does **not** cover R+4, the ceremony
verify, or the on-chain steps — those stay manual (see Sections 3 and 4).

```bash
cd <repo-root>/rseries-hardening
./reproduce.sh
```

The script guards each repo with an existence check and prints clear messages.
It assumes `npm install` can fetch dependencies; it does not assume any other
network access.

---

## Summary of expected results

| Step | Command | Expected |
|---|---|---|
| R+2 unit | `npm test` | all pass, exit 0 |
| R+2 conformance | `npm run conformance` | 10/10 vectors |
| R+2 scale | `npm run scale` | 10,000 receipts verified |
| R+2 adversarial | `node test/adversarial.test.js` | **9 passed + 1 documented nonce-uniqueness gap** |
| R+3 regression | `npm test` | 10/10 |
| R+3 adversarial | `npx tsx test/adversarial.test.ts` | 6/6 |
| R+4 witness | `npm test` | 7/7 |
| R+4 proof adversarial | `node test/adversarial-proof.test.mjs` | 10/10 |
| R+4 ceremony | `snarkjs zkey verify ...` | `ZKey Ok!` |
| On-chain | open explorer links | transactions/contracts confirmed |
