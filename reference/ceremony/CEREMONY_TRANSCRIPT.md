# R+4.5 Trusted-Setup Ceremony — Transcript (v0.1)

Completed **23 May 2026**. This is the public record of the R+4 Phase-2
trusted-setup ceremony for the `threshold-count-v1` circuit. It produced the
production proving/verifying keys behind the R+4 mainnet verifier.

## Result

- **Circuit:** `threshold-count.circom` — Groth16 / BN254, 1,197,221 R1CS constraints
- **Circuit hash:** `d1af28df 4f4e5b63 3958b4a0 bca2d305 38e961f7 c5787192 cc1d656a 4449a868 1cb511d5 5184279a ed1b04cf 64ec7bc9 713fcc86 5d30e115 aed3442e 55ff2837`
- **Contributors:** 5, chained in order
- **Random beacon:** Bitcoin block applied after all contributions
- **Verification:** `snarkjs zkey verify` → **`ZKey Ok!`**

## Contribution chain

| # | Contributor | Contribution hash |
|---|-------------|-------------------|
| 1 | dk-c1 (coordinator) | `2cbf998c c3a86974 43009930 98798935 dbc86863 6d889544 f7ead68f e6b2cdf0 bd490b3d 65d3cd62 a8cba62d 787b126d 160a30ee 9a14b670 71327ac0 842e4116` |
| 2 | c2-amy | `4a75673d e519af63 5c025ec4 36084518 9c5a81bb b480bdf7 2a29019f 1ab194d7 9f25a700 c0ae73d8 5a3030cd bbb9e5fd 75e0d894 27475b3d f8a34c9a 2391d557` |
| 3 | c3-ruchi | `f64846e4 5b125b31 b6c1773c 3e0b8b1f 11bda8dd 224ccec5 b0217296 b705bef9 9748f89e 1dc77e09 ef050fc2 40e3e2db c43015ed 5090f770 a09f4496 d7b5f0fa` |
| 4 | c4-manaj | `c658d7f0 b0a59757 543eb261 f5e85b4d 04ab959a 6c94077e c0844f84 98722e97 d317cf6b 5a16bc8d cc48d1e3 98d8c180 9bd1f26e ef4ef919 60e6b5df 3675675d` |
| 5 | c5-sahil | `c9a77430 aaaee5e3 ac642b9b 18f0ef38 84503c29 02a4c5b9 b0ba3da1 a92efd6e 58d4f32a e1b65ec1 bb2c394f aa366921 1d5d5653 d0a402a9 61da2638 8c696995` |
| 6 | beacon | `257f8e40 62d69780 4ad0a512 fd25e3f0 5ce098fc 43c31187 20b1e6b4 03ada20a e4c0d2b1 43580a2b 6d8c78b5 4cf29117 599d5a6c cf284437 9bdc71d0 a1e55a91` |

## Random beacon

- **Source:** Bitcoin block **950552**, mined 2026-05-23 00:15:21
- **Block hash:** `000000000000000000014bbb2806609a12f65d4628e8f45df2a4a51d58cca687`
- **Verify:** <https://mempool.space/block/000000000000000000014bbb2806609a12f65d4628e8f45df2a4a51d58cca687>
- **numIterationsExp:** 10
- Selected after all 5 contributions completed — unpredictable and unforgeable.

## Production verifier — Base mainnet

The production Groth16 Solidity verifier, built from this ceremony's
`phase2_final.zkey`, is deployed on Base mainnet:

- **Verifier contract:** `0xabf8626c20e6bf21a9fdcd4e9f80c17ac8963209`
  — <https://basescan.org/address/0xabf8626c20e6bf21a9fdcd4e9f80c17ac8963209>
- **Deploy tx:** `0x9df6edff61e9c63f25fbb1247a77a0f74cea128bb5a99427ea4bea902f01f53f`
- **Block:** 46343838 · **Network:** Base mainnet (chain ID 8453)

## Honest scope

This is a **v0.1 ceremony**. The 5 contributors were family members and DCS
Labs internal staff. It produced valid, verified production-format keys and a
live mainnet verifier — but the 1-of-N independence guarantee is only as
strong as the contributors' independence. A broader ceremony with fully
independent external contributors is the recommended follow-up. This ceremony
must always be described as: **"R+4 v0.1 ceremony — 5 contributors, family +
internal."**

## Independent verification

```
snarkjs zkey verify threshold-count.r1cs pot22_final.ptau phase2_final.zkey
```
reproduces `ZKey Ok!` and the contribution chain above.
