# R+4 Reference Implementation (v0.1)

**Spec:** [dcslabs.ai/standard/r4](https://dcslabs.ai/standard/r4)
**Status:** Reference sketch — circom sources + TypeScript prover/verifier scaffolds. Full implementation in progress at [github.com/DCS-LabsAI/r4-standard](https://github.com/DCS-LabsAI/r4-standard) (target: Q3 2026).

## What's here

```
r4-reference/
├── README.md                        # This file
├── circuits/
│   └── threshold-count.circom       # Reference circuit for r4-threshold-count-v1
├── prover/
│   └── prove.ts                     # TypeScript prover scaffold (snarkjs)
├── verifier/
│   └── verify.ts                    # TypeScript verifier scaffold (snarkjs)
├── solidity/
│   └── Groth16Verifier.sol          # On-chain verifier contract sketch
├── example-proof.json               # Example R+4 proof object
└── example-statement.json           # Example R+4 statement
```

## Quickstart (when full implementation lands)

```bash
# Install
npm install @trdnetwork/r4-prove @trdnetwork/r4-verify

# Generate a proof
npx r4-prove \
  --circuit r4-threshold-count-v1 \
  --bundle ./q1-2026-bundle.json \
  --statement ./statement.json \
  --out ./proof.json

# Verify
npx r4-verify ./proof.json --registry registry.r4.dcslabs.ai
# → [ ok ] groth16 verify : valid (8.3 ms)
```

## Profile

- **Default:** Groth16 over BN254 (Ethereum-friendly, ~250k gas on-chain)
- **Alternative:** PLONK over BLS12-381 (universal setup, larger proofs)
- **Future:** Halo2 + Nova folding (recursive, for N ≥ 1000 receipts)
- **Future v1.x:** STARK (post-quantum, no trusted setup)

## Statement classes shipped in v0.1

| Circuit ID | What it proves |
|---|---|
| `r4-threshold-count-v1` | ≥ N receipts in window with policy P and amount ≤ A |
| `r4-sum-bound-v1` | Total amount in window is in [L, U] |
| `r4-set-membership-v1` | Every receipt's principal is in allowlist A |
| `r4-uniqueness-v1` | No two receipts share a nonce (replay-free) |
| `r4-policy-conformance-v1` | Every receipt was signed under policy P |
| `r4-completeness-v1` | Bundle contains exactly the receipts matching selector Q |

## License

MIT. Same as R+2 and R+3.
