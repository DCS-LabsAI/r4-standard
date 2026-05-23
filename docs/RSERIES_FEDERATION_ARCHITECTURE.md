# R-Series Federation Architecture (R+4 Federation Layer)

**Document type:** Design specification
**Status:** Design — not yet implemented as a multi-node network
**Applies to:** DCS Labs R-Series trust stack, R+4 layer
**Version:** 0.1 (design draft)
**Date:** 2026-05-23

---

## 1. Purpose & Scope

The R-Series is a three-layer trust stack for AI-agent action accountability:

- **R+2** — signed, hash-chained action receipts (Ed25519). Each receipt commits to the prior receipt, producing a tamper-evident per-issuer chain.
- **R+3** — SHA-256 Merkle-rooted audit bundles aggregating R+2 receipts; bundle roots are anchored on-chain.
- **R+4** — Groth16 zero-knowledge proofs over the BN254 curve, computed over R+2/R+3 data. An R+4 proof demonstrates that a compliance property holds (for example, "every receipt in this bundle was signed by an authorised key" or "no action exceeded a declared spend limit") **without revealing the underlying receipts**.

R+4 works today in the **single-domain** case. A verified trusted-setup ceremony produced production proving and verifying keys, and a production verifier contract is live on Base mainnet at `0xabf8626c20e6bf21a9fdcd4e9f80c17ac8963209`. A single issuer can produce a proof and a verifier who already holds that issuer's verifying key can check it.

**What federation adds.** Today, every verifier must obtain each issuer's verifying key through an out-of-band, bilateral exchange. This does not scale: with *N* issuers and *M* verifiers, the system requires *O(N×M)* key-distribution relationships, each independently trusted and independently maintained. Federation replaces this mesh with a **shared, signed, versioned membership document** — the *federation manifest* — that enumerates which issuers are members and which circuits are accepted. Any member can produce an R+4 proof, and any other member or external verifier can check it by consulting one authenticated artefact rather than negotiating *N* separate key relationships.

**Honest scope statement.** This document is a **design specification**. Federation is **not built**. There is no live multi-node R-Series network. The first concrete deliverable described here is a *single-process reference module* (v0.1) that exercises the manifest and cross-issuer verification logic in one address space. Multi-node operation, synchronisation, and Byzantine hardening are later phases. Nothing in this document should be read as describing deployed infrastructure. Where a mechanism is aspirational, it is marked as such.

This document does **not** redesign R+2, R+3, or the R+4 circuit/proving system. It assumes them as given and specifies only the layer that coordinates trust *between* issuers.

---

## 2. Node Model

A **federation node** is a software process operated by one organisation that participates in the federation. A node is not a blockchain node and does not run consensus; it is a local service that holds federation state and answers verification queries.

A node holds the following state:

- **The current federation manifest** — the signed membership document (Section 3), retained at its currently trusted version.
- **A verifying-key store** — a map from circuit ID to the BN254 verifying key for that circuit. Keys are content-addressed by hash; the manifest binds circuit IDs to key hashes.
- **A peer list** — the network addresses (or content endpoints) of other nodes, used for manifest synchronisation. The peer list is operational metadata and is *not* itself a trust root; a node trusts a peer's *data* only after verifying signatures against the manifest, never because the peer is on the list.
- **Optionally, a manifest history** — prior manifest versions, retained to validate predecessor-hash chaining and to audit revocations.

A node operates in one or both of two **roles**:

- **Issuer role.** The node holds a proving key and one or more R+2/R+3 data sources. It produces R+4 proofs for compliance properties about its own activity. An issuer also holds the signing key registered under its issuer ID in the manifest. An issuer is identified by a stable **issuer ID** (a public-key fingerprint).
- **Verifier role.** The node checks R+4 proofs presented by others. It needs the manifest and the verifying-key store but no proving capability.

A single deployment commonly runs both roles. An **external verifier** — a party outside the federation — runs only the verifier role and may obtain the manifest read-only without operating a full node.

Nodes are mutually independent. There is no privileged "super-node." A **coordinator** role exists only for manifest authorship (Section 3) and holds no power to verify or reject proofs.

---

## 3. Federation Manifest

The manifest is the single authenticated artefact that defines federation membership.

### 3.1 Fields

| Field | Description |
|---|---|
| `manifest_version` | Monotonically increasing unsigned integer. |
| `federation_id` | Stable identifier for this federation. |
| `predecessor_hash` | SHA-256 hash of the previous manifest version's canonical serialisation; null only for version 1. |
| `members` | List of member records: `{ issuer_id, signing_pubkey, status, joined_version }`. |
| `circuits` | List of accepted circuit records: `{ circuit_id, verifying_key_hash, status, added_version }`. |
| `revocations` | Explicit list of revoked issuer IDs and revoked circuit IDs with the version at which revocation took effect. |
| `valid_from` / `valid_until` | Optional validity window. |
| `signatures` | Set of Ed25519 signatures from authoring signers over the canonical serialisation of all preceding fields. |

The manifest is serialised canonically (deterministic field ordering, fixed encoding) so that its hash is reproducible by any party.

### 3.2 Authorship and signing

A manifest is authored by a **coordinator** and must carry a **threshold of signatures** — *k-of-n* from a fixed signer set declared in the federation's founding configuration (the *root signer set*). The root signer set is the federation's bootstrap trust anchor; changing it requires a manifest signed under the *old* threshold that declares the *new* set, so signer-set rotation is itself chained and auditable.

### 3.3 Lifecycle and monotonicity

- **Version monotonicity.** A valid manifest at version *v+1* must carry `predecessor_hash` equal to the SHA-256 of the canonical version *v*. Versions never decrease and never skip. A node MUST reject any manifest whose version is not strictly greater than its current trusted version.
- **Predecessor-hash chaining.** The chain of `predecessor_hash` links forms a verifiable history. A verifier presented with version *v* and holding version *v−j* can confirm the intervening chain, detecting silent substitution of history.
- **On-chain anchoring.** For each accepted manifest version, the SHA-256 of its canonical serialisation is anchored on Base mainnet (a small registry transaction recording `federation_id → version → manifest_hash`). The anchor provides an independent, ordered, append-only witness: a verifier can confirm that the manifest hash it holds matches the hash anchored for that version, defeating off-chain forgery and equivocation (Section 6). Anchoring is *confirmation*, not *authorisation* — signatures authorise; the anchor records.

### 3.4 Adding and removing members and circuits

- **Add a member.** A new manifest version appends a `members` record with `status: active`. The new member's signing public key is now recognised.
- **Remove a member.** The member's record is set to `status: revoked` and an entry is added to `revocations`. The record is retained, not deleted, so historical proofs remain auditable against the version under which they were issued.
- **Add a circuit.** Append a `circuits` record binding `circuit_id` to `verifying_key_hash`.
- **Remove/deprecate a circuit.** Set `status: revoked` and record it in `revocations`.

Every change is a new signed version with a fresh on-chain anchor.

---

## 4. Cross-Issuer Verification Flow

A verifier presented with an R+4 proof `P`, claimed to be issued by `issuer_id = A` over `circuit_id = C`, performs the following:

1. **Obtain the manifest.** Retrieve the current federation manifest (from local cache, a peer, or a read-only endpoint).
2. **Verify the manifest signature.** Check that the manifest carries a valid *k-of-n* signature set from the root signer set. Reject otherwise.
3. **Verify the on-chain anchor.** Compute the SHA-256 of the manifest's canonical serialisation and confirm it matches the hash anchored on Base mainnet for `(federation_id, manifest_version)`. Reject on mismatch — this is the defence against an attacker presenting a validly *signed-but-superseded* or forged manifest.
4. **Verify version freshness.** Confirm the manifest version is at least as recent as the last version the verifier has seen; if older, attempt synchronisation (Section 5) before proceeding.
5. **Check issuer membership.** Confirm `A` appears in `members` with `status: active` and is not present in `revocations`. Reject otherwise.
6. **Check circuit acceptance.** Confirm `C` appears in `circuits` with `status: active` and is not revoked. Reject otherwise.
7. **Retrieve the verifying key.** Look up `C`'s `verifying_key_hash` from the manifest, fetch the corresponding verifying key from the key store, and confirm its hash matches. Reject on mismatch.
8. **Groth16 verification.** Run the Groth16/BN254 verification routine with the verifying key, the proof `P`, and the declared public inputs. Accept the proof only if verification succeeds.

The proof is accepted only if **all** steps pass. Steps 1–7 establish *authority to be trusted*; step 8 establishes *cryptographic validity*. Both are required.

---

## 5. Synchronisation Model

Nodes must converge on the current manifest version without a central server being a single point of failure.

**v0.2 — polling.** Each node periodically polls its peers and the on-chain registry for the latest `(version, manifest_hash)`. On discovering a higher version, it fetches the full manifest, runs the full validation (signature + anchor + predecessor chain back to its current version), and adopts it. Polling is simple and adequate for small federations; convergence latency is bounded by the poll interval.

**v1.0 — gossip.** Nodes push new-version announcements to peers on receipt, propagating updates in *O(log N)* hops rather than waiting for poll cycles. Gossip carries only `(version, manifest_hash, signer set)`; the full manifest is pulled and independently validated.

**Stale versions.** A node holding an older version is *safe but degraded*: it may wrongly reject a newly-added member or wrongly accept a member revoked after its version. Verifiers SHOULD treat a manifest older than a configurable staleness bound as a soft failure and refuse to finalise verification until resynchronised.

**Conflicting versions.** Two distinct manifests claiming the *same* version number is an equivocation event. The on-chain anchor is authoritative: only one hash can be anchored per `(federation_id, version)`. A node observing a signed manifest whose hash differs from the anchored hash for that version MUST reject it and SHOULD raise an alert. If two manifests are both unanchored, the node defers until the anchor resolves the conflict.

---

## 6. Byzantine & Adversarial Assumptions

The design assumes some federation participants may be faulty or malicious. What it defends:

- **Malicious member issuing false proofs.** A member cannot forge a Groth16 proof for a property that does not hold — soundness is cryptographic. A malicious member can only produce *true* proofs about its own (possibly misbehaving) activity, or refuse to produce proofs.
- **Forged manifest.** An attacker without *k* root signing keys cannot produce a manifest that passes step 2. Even with valid signatures on a stale version, the on-chain anchor (step 3) reveals the forgery.
- **Equivocating coordinator.** A coordinator that signs two different manifests at the same version is defeated by the anchor: only one hash is anchored per version, and every verifier checks against it.
- **Replayed / rolled-back manifest.** Strict version monotonicity (step 4) plus predecessor-hash chaining means a node never accepts a version below its current one. An attacker cannot revive a revoked member by replaying an old manifest.
- **Key compromise of a member.** A compromised member signing key is contained by revocation (Section 7): a new manifest version revokes the member or rotates its key, and the anchor propagates the change.

What the design does **not** defend:

- **Compromise of *k* root signers.** If an attacker controls a signing threshold, they can author arbitrary valid, anchorable manifests. The root signer set is the trust floor; its protection is operational, not cryptographic.
- **Garbage-in proofs.** R+4 proves a property over R+2/R+3 data *as supplied*. If a malicious issuer fabricates its own receipt chain consistently, R+4 will faithfully prove a property of fabricated data. Federation does not attest to the *truthfulness* of an issuer's underlying activity, only to membership and proof validity.
- **Liveness against censorship.** A network adversary can delay manifest propagation. The design provides safety (no wrong accept) under delay, not guaranteed liveness.
- **Chain-level attacks** — a reorg of the anchoring chain, or compromise of the registry contract, is out of scope and inherited from Base's security model.

---

## 7. Revocation Propagation

Revocation is the security-critical path: a removed member or revoked key must reach every verifier promptly.

1. **Authoring.** The coordinator publishes a new manifest version with the affected `members`/`circuits` record set to `status: revoked` and an explicit `revocations` entry recording the effective version.
2. **Anchoring.** The new manifest hash is anchored on Base mainnet, creating an immutable, timestamped record of the revocation.
3. **Propagation.** Nodes adopt the new version via the synchronisation model (Section 5) — gossip in v1.0, polling in v0.2.
4. **Enforcement.** Once a verifier holds the new version, steps 5–6 of the verification flow reject any proof from the revoked issuer or circuit.

**Propagation latency** equals synchronisation latency: bounded by the poll interval (v0.2) or gossip depth (v1.0). To limit the exposure window, verifiers SHOULD enforce a staleness bound (Section 5) so they cannot keep accepting a revoked member indefinitely while running an old manifest. Revocation is **not retroactive**: a proof validly issued and verified under an earlier version remains historically valid; revocation prevents *future* acceptance. Auditors evaluating a past proof must evaluate it against the manifest version in force at issuance time.

---

## 8. Trust Assumptions

A verifier in this federation must trust the following, explicitly:

- **The root signer set, under a *k-of-n* assumption.** The verifier trusts that fewer than *k* of the *n* root signers are compromised. This is a *1-of-N-style* honesty assumption inverted: the system is safe as long as the adversary controls fewer than the threshold. The verifier does **not** need to trust any individual signer.
- **The anchoring chain.** The verifier trusts Base mainnet to provide an append-only, non-equivocating record of `(federation_id, version, manifest_hash)`.
- **The cryptographic primitives** — Ed25519 signatures, SHA-256, and the Groth16/BN254 proving system with its verified trusted-setup output.
- **The honesty of its own software** — that its node correctly performs steps 1–8.

A verifier does **not** need to trust: any individual issuer, the coordinator's intentions (only its threshold-signed output, cross-checked against the anchor), the peer that delivered the manifest, or any bilateral key exchange. This reduction — from *O(N×M)* pairwise trust to one signer-set assumption plus one chain assumption — is the core value of federation.

---

## 9. Phased Delivery Plan

**v0.1 — Single-process reference module.** *Scope:* manifest data model, canonical serialisation, build/sign/verify (k-of-n Ed25519), predecessor-hash chaining, and the full cross-issuer verification flow (Section 4) — all in one address space with simulated multiple issuers. On-chain anchoring is *stubbed* with a local hash table standing in for the registry. *Goal:* prove the manifest and verification logic are correct and the cross-issuer path is sound. *Effort estimate:* small — single developer, a few weeks. This is the **next concrete deliverable** and the honest current horizon.

**v0.2 — Real multi-node with polling sync.** *Scope:* split the reference into independently running nodes; real network transport; peer lists; the polling synchronisation model (Section 5); a real (testnet first, then mainnet) on-chain manifest registry contract and anchor verification. *Goal:* a working small federation with genuine network separation. *Effort estimate:* moderate — registry contract, transport, deployment tooling, integration testing across nodes. Multiple weeks to a few months.

**v1.0 — Gossip, Byzantine hardening, production registry.** *Scope:* gossip-based propagation; staleness-bound enforcement; equivocation detection and alerting; conflict resolution against the anchor; signer-set rotation; operational revocation runbooks; monitoring; external-verifier read-only distribution. *Goal:* a federation safe to run with mutually distrusting members at meaningful scale. *Effort estimate:* substantial — this is the bulk of the engineering and security-review effort, and should not be compressed.

---

## 10. Open Questions & Risks

- **Root signer-set governance.** Who holds the *n* root keys, how is *k* chosen, and how is signer rotation operated securely? This is an organisational problem the cryptography cannot solve.
- **Anchoring cost and rate.** Frequent membership changes mean frequent on-chain transactions; gas cost and confirmation latency may bound how fast revocation can propagate. A batching or checkpoint scheme may be needed.
- **Manifest size growth.** Retaining revoked records forever keeps the manifest auditable but unbounded in size. A snapshot-plus-delta or archival scheme is an open design point.
- **Verifying-key distribution.** The manifest binds circuit IDs to key *hashes*, but the keys themselves still need a distribution channel and an integrity check on retrieval. Where keys are hosted and cached is unspecified.
- **Cross-federation interop.** Multiple federations with distinct root signer sets are out of scope here; bridging them is future work.
- **Staleness bound tuning.** Too tight harms availability; too loose widens the revocation exposure window. The right value is deployment-specific and needs empirical input.
- **Coordinator availability.** Although the coordinator holds no verification power, a federation with no available coordinator cannot publish membership changes. Coordinator redundancy is unaddressed.
- **Registry contract upgradeability.** A bug in the on-chain manifest registry would be serious; its upgrade/governance model needs the same scrutiny as the verifier contract.

---

*This document describes a design and a forthcoming single-process reference module. It does not describe a live multi-node network. Claims of deployed federation infrastructure would be inaccurate as of this version.*
