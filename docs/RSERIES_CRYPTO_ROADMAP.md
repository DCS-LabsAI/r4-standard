# R-Series Cryptographic Roadmap

**DCS Labs — AI-Agent Trust Stack**
Status: research-stage working document
Last revised: 2026-05-23

---

## 0. Scope and intent

This document records the cryptographic choices made across the R-Series trust
stack (R+2 through R+4), states *why* each choice was made, and lays out an
honest upgrade path. It is written for a technically critical reviewer — the
kind who reads "Groth16" and immediately asks *"why Groth16, what's the trusted
setup story, and what happens when BN254 ages out?"* Those questions are
answered directly below.

Nothing in the "migration path" or "post-quantum" sections describes shipped
code. Those are roadmap items. The only profile in production today is
**R+4 v0.1: Groth16 over BN254**, which targets *classical* security only.

---

## 1. Current choices and why

### 1.1 R+2 — signed canonical receipts

R+2 produces per-action receipts that are individually signed and hash-chained.

- **Ed25519 (RFC 8032) signatures.** Ed25519 is a deterministic EdDSA scheme
  over Curve25519. We chose it for: deterministic nonces (no catastrophic
  failure from a bad RNG, unlike ECDSA), small keys and signatures (32-byte
  public keys, 64-byte signatures), fast batch verification, and near-universal
  library support. It carries a comfortable ~128-bit classical security margin.
- **RFC 8785 canonical JSON (JCS).** A signature is only meaningful if signer
  and verifier agree byte-for-byte on *what* was signed. JSON has many valid
  serializations of the same logical object (key order, whitespace, number
  formatting). RFC 8785 (JSON Canonicalization Scheme) fixes a single
  deterministic encoding, so the hash of a receipt is reproducible by any
  independent verifier. We sign the JCS-canonical bytes, not raw JSON.
- **SHA-256 hash chaining.** Each receipt commits to the SHA-256 digest of its
  predecessor, forming an append-only chain. Tampering with any historical
  receipt invalidates every digest after it. SHA-256 is chosen for ubiquity,
  hardware acceleration, and a strong, well-studied collision-resistance record.

### 1.2 R+3 — Merkle-batched bundles

R+3 aggregates many R+2 receipts into a single verifiable bundle.

- **SHA-256 binary Merkle trees.** Receipts are leaves of a binary Merkle tree.
  This gives O(log n) inclusion proofs and a single 32-byte root that commits to
  the entire bundle. Reusing SHA-256 keeps the hashing primitive consistent with
  R+2's chain.
- **Ed25519 bundle signatures.** The Merkle root is signed once with Ed25519,
  so an entire batch of receipts is authenticated by one signature, while any
  individual receipt can still be proven present against the signed root.

### 1.3 R+4 — zero-knowledge threshold proofs

R+4 proves statements *about* receipt sets without revealing the receipts —
specifically, that a threshold count of qualifying receipts exists.

- **Proving system: Groth16.**
- **Curve: BN254** (a.k.a. alt-bn128), a pairing-friendly curve.
- **Circuit:** `threshold-count.circom`, **1,197,221 R1CS constraints**.
- **Keys:** produced by a **Phase-2 multi-party trusted-setup ceremony**
  (a Powers-of-Tau power-22 universal phase, followed by a per-circuit Phase 2).
- **On-chain:** a Groth16 Solidity verifier is **deployed on Base mainnet**.

#### Why Groth16 over BN254

Groth16 was selected deliberately, with eyes open to its cost:

1. **Constant-size proofs (~200 bytes).** A Groth16 proof is three group
   elements regardless of circuit size. ~1.2M constraints and ~12 constraints
   produce the same proof size. This matters for storage and on-chain posting.
2. **Cheap on-chain verification via the EVM pairing precompile.** Ethereum —
   and therefore Base — exposes BN254 pairing and curve operations as
   precompiled contracts (EIP-196 / EIP-197). Groth16 verification is a fixed
   handful of pairing checks, so on-chain verification is *cheap and constant
   cost*. This is the single biggest reason BN254 was chosen over higher-margin
   curves: it is the curve the EVM can verify natively today.
3. **Mature tooling.** circom + snarkjs is a well-trodden, audited-by-usage
   toolchain for Groth16/BN254. Building R+4 v0.x on it minimized
   implementation risk for a first production profile.

#### The honest trade-off

Groth16 requires a **per-circuit trusted setup**. The structured reference
string is circuit-specific: *any change to `threshold-count.circom` requires a
fresh Phase-2 ceremony.* If the toxic waste from that ceremony were not
destroyed, a holder could forge proofs. We mitigate this with a multi-party
ceremony (security holds if *at least one* participant is honest and discards
their contribution), but the structural cost remains: **Groth16 does not scale
gracefully to many circuits or frequent circuit changes.** That limitation is
the primary driver of the migration path in Section 3.

---

## 2. Known limitations

We state these plainly rather than burying them.

- **BN254 has a degraded security margin.** When BN254 was designed it was
  estimated at ~128-bit security. Advances in the tower-number-field-sieve
  family of attacks against pairing-friendly curves have since reduced the
  effective margin to roughly **~100 bits**. That is still far outside brute
  force, but it is *below* the 128-bit target we hold elsewhere in the stack,
  and it is not a curve we would choose for a long-lived, high-assurance system.
- **Per-circuit ceremony trust.** As noted, Groth16 soundness depends on the
  Phase-2 ceremony's toxic waste being destroyed. This is a real, ongoing trust
  assumption — not a one-time concern — because every circuit revision repeats
  it.
- **Not post-quantum.** BN254's security, and Groth16's soundness, rest on the
  hardness of discrete logarithm / pairing-based assumptions. These are broken
  by a sufficiently large quantum computer running Shor's algorithm. R+4 v0.x is
  a **classical-security** system. See Section 4.

---

## 3. Migration path

The roadmap below addresses two distinct pressures: (a) the per-circuit
ceremony cost, and (b) BN254's aging margin and lack of PQ resistance. No
profile below is built today.

### 3.1 PLONK — universal and updatable setup

**What it changes.** PLONK uses a *universal* SRS: one trusted setup supports
*any* circuit up to a bounded size, and the setup is *updatable* — new
participants can contribute later. Adopting PLONK would **eliminate the
per-circuit Phase-2 ceremony.** New or revised circuits would reuse the existing
universal SRS with no new ceremony.

**Cost.** PLONK proofs are larger than Groth16's (~400+ bytes vs ~200 bytes) and
on-chain verification is somewhat more expensive, though still feasible on Base.

**When DCS would move.** When the number of distinct circuits, or the frequency
of circuit revisions, makes repeated Phase-2 ceremonies the dominant operational
cost. This is the most likely *first* migration because it is the most direct
fix for R+4's biggest structural weakness while staying on EVM-friendly
pairing curves.

### 3.2 STARKs — no trusted setup, PQ-plausible

**What it changes.** STARKs use only collision-resistant hash functions and
require **no trusted setup at all** — eliminating ceremony trust entirely. Being
hash-based, they are considered **post-quantum-plausible** (their security does
not rest on discrete log).

**Cost.** STARK proofs are *much* larger (tens to hundreds of kilobytes) and
on-chain verification is correspondingly more expensive. This is a real cost
for a system that posts proofs on-chain.

**When DCS would move.** As the long-horizon target for a post-quantum R+4
profile, or wherever eliminating *all* setup trust is worth the proof-size cost.
A STARK-based R+4 is the natural endpoint of the PQ path in Section 4.

### 3.3 Recursive proofs / folding — scaling to large receipt counts

**What it changes.** Recursion (Halo2) and folding (Nova) let one proof attest
to many sub-proofs, amortizing verification. As R-Series receipt volumes grow,
proving the *entire* history in one shot becomes impractical; recursion lets a
single succinct proof cover an arbitrarily long chain of prior proofs. Halo2
additionally avoids per-circuit trusted setup.

**Cost.** Higher prover complexity and implementation effort; the recursion
itself must be carefully engineered.

**When DCS would move.** When receipt/bundle counts grow large enough that
single-shot proving cost or proof-aggregation latency becomes the bottleneck.
This is a *scaling* upgrade and is largely orthogonal to the curve/PQ choice —
it could be layered on a PLONK or STARK base.

---

## 4. Post-quantum considerations

This is stated without hype: **R+4 v0.x targets classical security only. DCS
Labs does not claim post-quantum security today.**

- **The exposure.** BN254 and Groth16 rest on discrete-log and pairing
  hardness. Shor's algorithm, on a sufficiently capable quantum computer, breaks
  both. The same applies to Ed25519 (Curve25519 discrete log). A
  cryptographically relevant quantum computer does not exist today, but the
  exposure is real for long-lived signed records.
- **What is comparatively robust.** The **hash-based components age much
  better.** SHA-256 hash chaining (R+2) and SHA-256 Merkle trees (R+3) face only
  Grover's algorithm, which yields a quadratic speedup — addressed by margin,
  not by a structural break. The hash-based parts of the stack are
  *comparatively PQ-robust*; the signature and zk-SNARK parts are not.
- **Interim mitigation — BLS12-381.** Before any full PQ transition, R+4 could
  migrate its pairing curve from BN254 to **BLS12-381**, which restores a
  ~128-bit classical margin. This is *not* post-quantum — it is still
  discrete-log-based — but it removes the degraded-margin concern of Section 2
  as a measured interim step.
- **Long-horizon PQ path.** A genuinely post-quantum R+4 means a **STARK-based
  profile** (Section 3.2): hash-based, no trusted setup, no discrete-log
  dependency. Signatures (R+2/R+3) would correspondingly need a PQ scheme
  (hash-based or lattice-based) in the same horizon. This is a research target,
  not a committed delivery.

---

## 5. Universal-setup exploration

Adopting a PLONK-style **universal SRS** would change R-Series operations as
follows:

- **No ceremony per new circuit.** Today, shipping a new R+4 circuit, or
  revising `threshold-count.circom`, requires organizing a fresh multi-party
  Phase-2 ceremony — a slow, coordination-heavy process. A universal SRS is run
  *once* and reused for every circuit up to its size bound.
- **Faster circuit iteration.** Circuit changes become a normal software
  release rather than a ceremony event. This materially lowers the cost of
  evolving R+4's proven statements.
- **Updatable trust.** The universal SRS can accept new contributions over time,
  so the trust base can be *strengthened* after deployment rather than frozen at
  ceremony time.
- **The remaining cost.** The universal SRS is still a trusted setup — it is
  *one* ceremony, not *zero*. Only a STARK-based profile removes setup trust
  entirely. Universal setup is best understood as the pragmatic middle ground:
  it removes the *per-circuit repetition* without the proof-size penalty of
  STARKs.

---

## 6. Version table

| Horizon       | Profile                          | Signatures           | ZK proof system        | Setup                          | Security target                  | Status        |
|---------------|----------------------------------|----------------------|------------------------|--------------------------------|-----------------------------------|---------------|
| **Current**   | R+4 **v0.1**                     | Ed25519              | Groth16 over BN254     | Per-circuit Phase-2 ceremony   | Classical (~100-bit, BN254)       | **Production** |
| **Near-term** | R+4 **v0.x** universal-setup     | Ed25519              | PLONK (universal SRS)  | One universal, updatable SRS   | Classical; BLS12-381 as margin upgrade | Roadmap   |
| **Mid-term**  | R+4 recursive/folding            | Ed25519              | Halo2 / Nova           | Universal or none (Halo2)      | Classical; scaling-focused        | Roadmap       |
| **Long-term** | R+4 **PQ profile**               | PQ signature scheme  | STARK                  | **None**                       | Post-quantum-plausible            | Research      |

---

## 7. Summary

R+4 v0.1 chose Groth16 over BN254 for concrete, defensible reasons: ~200-byte
constant-size proofs, native EVM pairing-precompile verification on Base, and
mature circom/snarkjs tooling. The accepted cost is a per-circuit trusted setup
and a BN254 curve whose effective margin has eroded to ~100 bits. The stack is
classical-security only; it is not post-quantum.

The upgrade path is staged and honest: **PLONK** removes the per-circuit
ceremony via a universal updatable SRS; **recursion/folding** addresses scale;
**STARKs** are the long-horizon route to a setup-free, post-quantum-plausible
profile, with **BLS12-381** available as an interim higher-margin curve. The
hash-based components (SHA-256 chaining and Merkle trees) already age well
against quantum attack; the signature and SNARK layers are where the PQ work
will be required.

These are roadmap items. None of the near-, mid-, or long-term profiles is
implemented today.
