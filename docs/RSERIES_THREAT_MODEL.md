# DCS Labs R-Series — Threat Model

**Document status:** Formal threat model, v1.1
**Date:** 2026-05-23 (rev 1.1 — federation status updated from "specification only" to "working multi-node prototype")
**Audience:** Internal security, external auditors, regulators
**Subject:** The R-Series three-layer AI-agent trust stack (R+2, R+3, R+4)

---

## 1. Scope & Purpose

This document is a formal threat model for the DCS Labs **R-Series**, a three-layer trust stack for AI-agent accountability. The layers are:

- **R+2 — Open Provenance Standard.** Signed, hash-chained agent-action receipts.
- **R+3 — Tamper-Evident Audit Export.** Signed, Merkle-committed aggregation of R+2 receipts into audit bundles.
- **R+4 — Federated Zero-Knowledge Verification.** Groth16/BN254 zero-knowledge proofs over R+2 receipts and R+3 bundles, proving compliance properties without disclosing the underlying receipts.

The purpose of this document is to state, precisely and without overclaiming, **what each layer defends against, how, and what it does not defend against.** It is written so that an auditor or regulator can rely on it as an accurate account of the security posture.

**Maturity disclosure.** R+2 and R+3 are **operational prototypes**: functional and deployed, but not hardened or independently audited. R+4 is a **real cryptographic prototype**: the proving circuit and verification are genuine and exercised, but the layer is not production-hardened. **R+4 federation is now a working multi-node prototype** — multi-issuer aggregation, cross-node manifest synchronization and revocation propagation run across real node processes over HTTP and are exercised by a 13/13 multi-node test — **but it is NOT production-hardened: it has no TLS, no peer authentication, and no hardened Byzantine-fault-tolerant consensus.** Every claim below is bounded by this maturity statement.

This document does **not** make any claim involving artificial general intelligence or post-quantum security. Ed25519 and BN254 are classical-security primitives and are treated as such throughout.

---

## 2. Definitions

### 2.1 Adversary assumptions

We consider the following adversary classes:

- **A1 — External network adversary.** Can observe, replay, reorder, and inject messages, including receipts, bundles, and proofs. Cannot break Ed25519, SHA-256, or Groth16/BN254 soundness within classical bounds.
- **A2 — Malicious agent operator.** Controls one or more agents and their signing keys; may sign arbitrary or false receipts; may selectively withhold receipts.
- **A3 — Key-compromise adversary.** Has obtained an agent's Ed25519 private key through theft, exfiltration, or insider access.
- **A4 — Malicious verifier / relying party.** May misreport verification results downstream; out of scope for cryptographic mitigation but noted where relevant.
- **A5 — Ceremony adversary.** Participated in, or colluded with participants of, the R+4 trusted-setup ceremony and retained toxic waste.

We assume the adversary **cannot** forge Ed25519 signatures, find SHA-256 collisions, or break Groth16 soundness on BN254 within classical computational bounds.

### 2.2 Trust assumptions

- The **Ed25519** signature scheme (RFC 8032) and **RFC 8785** JSON canonicalization are correct as specified.
- **SHA-256** is collision- and preimage-resistant.
- The **Base mainnet** chain provides immutability and liveness for published agent public keys (`TRDWorkerSBT`, `0xbDd1f5fC349D9a8EfCEb07Edbd491233b2540f5F`) and for anchored Merkle roots.
- For R+4, soundness depends on **at least one of the five** trusted-setup contributors having securely destroyed their toxic waste. **This is a v0.1 ceremony: 5 contributors drawn from family and internal staff, with a Bitcoin-block beacon and a verified "ZKey Ok" check. The 1-of-N independence guarantee is only as strong as the independence of those contributors — and a family-plus-internal cohort is NOT a strong independence assumption.** This is stated plainly so relying parties can weigh it.

### 2.3 Failure assumptions

- A layer may fail **silently** (accepting invalid input) or **loudly** (rejecting valid input). Loud failure is preferred and is the design default.
- Prototype layers (R+2, R+3) may contain implementation bugs not yet found by audit.
- The absence of adversarial-resilience testing (see §7) means failure modes may exist that this model does not enumerate.

---

## 3. Threat Catalogue — OWASP Top 10 for Agentic Applications (December 2025)

This section maps the R-Series against the **OWASP Top 10 for Agentic Applications (December 2025)**. The R-Series is an **accountability and verification stack**, not an agent runtime. It therefore addresses these threats primarily by making agent actions **attributable, tamper-evident, and auditable after the fact** — it does not, in general, *prevent* an agent from being subverted.

### 3.1 Goal hijacking
*An adversary manipulates an agent into pursuing an attacker-chosen objective.*
**Coverage:** Indirect. The R-Series does not prevent goal hijacking. R+2 makes each hijacked action a **signed, hash-chained receipt**, so the hijack is detectable and attributable post hoc; R+3 makes a body of such actions tamper-evidently exportable for audit. **Uncovered:** prevention, real-time detection, and intent inference are entirely out of scope.

### 3.2 Tool misuse
*An agent is induced to invoke tools in harmful ways.*
**Coverage:** Indirect. R+2 receipts record tool-action provenance in the 11-field schema, enabling reconstruction of which agent invoked what. **Uncovered:** authorization of tool calls and runtime sandboxing are not provided by any R-Series layer.

### 3.3 Identity & agent-authentication abuse
*An adversary impersonates an agent or forges its identity.*
**Coverage:** Direct, strong. Every R+2 receipt carries an Ed25519 signature; the verifier performs a **pubkey match** against the agent identity published on-chain via `TRDWorkerSBT`. An adversary without the private key cannot produce a receipt that verifies. **Uncovered:** if the key itself is compromised (A3), the on-chain identity binding does not help — see §6.

### 3.4 Memory & context poisoning
*An adversary corrupts an agent's memory or context to influence future behavior.*
**Coverage:** None preventively; weak detective. The R-Series does not protect agent memory. If poisoned context leads to actions, those actions are receipted by R+2, so the *consequences* are auditable — but the poisoning itself is invisible to the stack. **Stated plainly: no R-Series layer mitigates memory or context poisoning.**

### 3.5 Cascading / multi-agent failures
*A fault or compromise in one agent propagates across a multi-agent system.*
**Coverage:** Detective only, and **incomplete**. R+2 chains link receipts per agent; R+3 can aggregate across agents into one bundle, supporting post-incident reconstruction. However, **cross-agent correlation depends on R+4 federation, which is a multi-node prototype, not production-hardened.** The federation prototype demonstrates cross-node manifest sync and revocation propagation, but without production-grade Byzantine fault tolerance the stack cannot yet give a *trustworthy* cross-node view of a cascading failure under adversarial nodes.

### 3.6 Rogue agents
*An agent operates outside its sanctioned mandate.*
**Coverage:** Detective. A rogue agent still signs receipts with its own key; its actions are attributable and its chain is inspectable. R+4 can prove aggregate compliance properties (e.g. policy adherence) over its receipts. **Uncovered:** the stack does not stop a rogue agent from acting, and a rogue agent may simply **decline to emit receipts** — see §3.8 and §4.2.

### 3.7 Privilege & credential abuse
*An adversary abuses elevated privileges or stolen credentials.*
**Coverage:** Partial. On-chain identity binding ensures a receipt is attributable to the credential that signed it, narrowing the abuse to a specific key. **Uncovered:** the R-Series does not manage, scope, or rotate agent privileges; credential abuse with a valid key produces valid receipts (A3).

### 3.8 Untraceable actions
*An adversary causes agent actions that cannot be attributed or audited.*
**Coverage:** Direct, strong — within a known limit. This is the central threat the R-Series is built to address. R+2 makes every *recorded* action a signed, hash-chained receipt; R+3 makes a *recorded* corpus tamper-evidently committed; R+4 lets a holder prove properties of that corpus without disclosure. **Critical limit: the stack guarantees integrity of receipts that exist, not the existence of receipts. An action for which no receipt is emitted is invisible.** Completeness ("all actions were receipted") is **not** asserted — see §7.

---

## 4. Per-Layer Threat Sections

### 4.1 R+2 — Open Provenance Standard

R+2 produces an 11-field receipt, canonicalized per **RFC 8785**, signed with **Ed25519 (RFC 8032)**, and chained to its predecessor by content hash. The verifier checks: schema, spec version (`r2/v0.1`), pubkey match, signature, chain pointer, and timestamp.

- **Malicious signer (A2).** A signer can sign *false* content. R+2 guarantees only **integrity and attribution**, not truthfulness. A false receipt is cryptographically valid; the mitigation is non-repudiable attribution to the signer, not prevention.
- **Key compromise (A3).** A stolen private key lets the adversary mint receipts indistinguishable from genuine ones. R+2 has **no in-band detection** of this. Recovery depends on on-chain key revocation/rotation in `TRDWorkerSBT` — see §6.
- **Replay / nonce reuse.** Receipts are chained by content hash; re-presenting an old receipt is detectable *within a chain* because the chain pointer fixes position. However, R+2 has **no standalone nonce**; a verifier that checks a receipt in isolation, outside chain context, cannot detect replay. Freshness must be enforced by the relying party (e.g. via timestamp window plus chain-tip check).
- **Timestamp ambiguity.** The receipt timestamp is **issuer-asserted**, not from a trusted time source. A malicious or misconfigured signer can backdate or postdate. The verifier checks the timestamp for plausibility but cannot prove it. Timestamps are **advisory**, not authoritative.
- **Partial-chain corruption.** Removing or altering a mid-chain receipt breaks the hash linkage and is detected on verification. But **truncation at the tip** — dropping the most recent receipts — is *not* detectable from the chain alone, because nothing yet points past the tip. This is the receipt-omission problem (§4.2) at the chain level.

### 4.2 R+3 — Tamper-Evident Audit Export

R+3 aggregates many R+2 receipts into a single signed **SHA-256 Merkle-committed** bundle, optionally anchored on-chain via a 0-value transaction carrying the 32-byte Merkle root in calldata. It provides logarithmic-size inclusion proofs.

- **Forged bundle.** A bundle is signed; a forged bundle requires the signer's key. Tampering with any included receipt changes the Merkle root and breaks both the signature and any anchor. Strongly mitigated.
- **Receipt omission / selective non-disclosure (A2).** This is R+3's principal residual weakness. The Merkle commitment proves **inclusion** of what is in the bundle; it does **not** prove **completeness**. A malicious exporter can build a bundle that omits inconvenient receipts, and the bundle still verifies perfectly. **R+3 does not, and cannot on its own, detect selective omission.**
- **Anchor spoofing.** The on-chain anchor is a 0-value transaction; a verifier must confirm it originates from the **expected sender address** and carries the **expected root**. An adversary can post a transaction with an unrelated root; if a verifier matches on root value alone without checking provenance, they can be misled. Anchor verification must bind sender, root, and chain.
- **Canonicalization divergence.** R+3 integrity assumes every node serializes receipts identically (RFC 8785). A divergent or buggy canonicalizer yields a different hash for semantically identical data, causing **false rejection** or, worse, a commitment that does not match peers. This is a real prototype risk and is not yet covered by conformance testing.
- **Replay.** A valid old bundle can be re-presented as current. Bundles carry the signer's identity but no enforced freshness field; relying parties must track the latest bundle per issuer.

### 4.3 R+4 — Federated Zero-Knowledge Verification

R+4 uses **Groth16 proofs over BN254** to prove compliance properties (e.g. "≥10,000 receipts under policy P") without revealing receipts. The circuit `threshold-count.circom` has **1,197,221 R1CS constraints**. Production keys came from a **5-contributor trusted-setup ceremony (v0.1)**.

- **Circuit soundness bugs.** Groth16 is sound only if the circuit **correctly encodes the intended statement**. An under-constrained `threshold-count.circom` could allow a valid proof of a false claim. The circuit has **not undergone independent formal review or audit**; soundness at the circuit level is currently an unverified assumption.
- **Trusted-setup toxic waste / ceremony trust.** Groth16 requires a per-circuit trusted setup. If **all five** v0.1 contributors' secret randomness were recovered or colluded, an adversary could forge proofs. The 1-of-N honesty assumption is only as strong as contributor independence — and the **v0.1 cohort is family plus internal staff, which is not independent in any adversarially meaningful sense.** The Bitcoin-block beacon and "ZKey Ok" check confirm the ceremony ran correctly; they do **not** establish contributor independence. **This is the single largest trust assumption in the stack and is explicitly flagged for re-ceremony before any high-assurance use.**
- **Proof replay / freshness.** A Groth16 proof is a fixed artifact; it can be replayed. R+4 proofs do **not** intrinsically bind to time or to a fresh challenge. Freshness must be imposed by including a nonce or epoch as a public input, which is **not currently enforced**.
- **Curve-level attacks on BN254.** BN254 offers roughly **100–110 bits** of security against the best-known attacks (notably advances in the tower-NFS family), below the 128-bit level often assumed. This is a classical-cryptanalysis caveat, not a quantum one. It is adequate for a prototype but should be reviewed; migration to a higher-security curve is a known future item.
- **Composition risk.** R+4 proves statements **about** R+2 receipts and R+3 bundles. It therefore **inherits every weakness of those layers**: it can faithfully prove a property of a corpus that was itself incomplete (§4.2) or built from false-but-signed receipts (§4.1). A valid R+4 proof attests to the *math over the inputs*, never to the *honesty of the inputs*.
- **Federation.** Cross-issuer R+4 verification is now a **working multi-node prototype**: `node-server.ts` runs federation nodes as real HTTP processes, and a `multinode.test.ts` run spawned 3 real node processes that synced a federation manifest, propagated a revocation, and rejected forged manifests over HTTP (13/13). **It is not production-hardened** — no TLS, no peer authentication, and no hardened Byzantine-fault-tolerant consensus — so no Byzantine guarantee exists against a malicious or colluding node. Single-domain R+4 (one issuer) remains the only configuration with a live mainnet verifier.

---

## 5. Replay Guarantees

The R-Series provides **bounded** replay protection:

- **What it guarantees.** Within a single R+2 chain, a receipt's position is fixed by its hash-chain pointer; re-inserting a duplicate is detectable on verification. Tampering with any committed receipt invalidates R+3 Merkle proofs and signatures.
- **What it does NOT guarantee.** No layer enforces standalone freshness. An old but valid R+2 receipt, R+3 bundle, or R+4 proof can be **re-presented to a verifier that lacks chain/epoch context** and will pass. Replay resistance is therefore the **relying party's responsibility**: it must track chain tips, latest bundles per issuer, and (for R+4) bind proofs to a nonce or epoch. The stack provides the material to detect replay; it does not automatically reject it.

"Replayability" of an *audit* — re-verifying a historical receipt set and obtaining the same result — **is** supported and is a design goal. Replay *resistance* against an adversary re-submitting stale artifacts as current **is not** fully provided today.

---

## 6. Key-Compromise & Recovery Model

- **R+2.** Agent identity is bound to an Ed25519 key published in `TRDWorkerSBT` on Base mainnet. On compromise (A3), the adversary can mint valid receipts until the key is revoked. Recovery is **revoke-and-rotate**: mark the compromised key invalid on-chain and issue a new key. **Receipts signed before revocation remain cryptographically valid** — verifiers must apply a revocation cutoff by timestamp, which is itself issuer-asserted and therefore imperfect (§4.1). There is no automatic compromise detection.
- **R+3.** A compromised bundle-signing key allows forged bundles. Recovery follows the same revoke-and-rotate path. Previously anchored bundles remain on-chain and must be re-evaluated against the revocation record.
- **R+4.** Two distinct key-compromise concerns: (a) the **proving/verification keys** from the trusted setup — compromise here is the toxic-waste scenario (§4.3) and is **not recoverable by rotation**; it requires a **new ceremony and re-deployment of the verifier**; (b) issuer signing keys feeding the proofs — handled as in R+2/R+3.

There is currently **no automated revocation-propagation mechanism** across relying parties; revocation is published on-chain but consumers must poll and enforce it themselves.

---

## 7. Out of Scope / Not Yet Mitigated

The following are explicitly **not mitigated** by the current R-Series and must not be assumed by any relying party:

- **Federation Byzantine faults.** Multi-issuer aggregation and cross-node synchronization are now implemented in a **multi-node prototype**, but **production-grade Byzantine fault tolerance is not**. No guarantee exists against a faulty or malicious node in a federated deployment; the prototype rejects forged manifests over HTTP but has not been hardened against a colluding or adversarial node.
- **Completeness assertions.** No layer proves that *all* agent actions were receipted. The stack secures the receipts that exist; it cannot attest that none were withheld (§3.8, §4.2).
- **Independent-node attestation.** There is no mechanism for one node to attest to the honest operation of another. R+4's "ZKey Ok" and the ceremony beacon attest to *ceremony correctness*, not to *node or contributor independence*.
- **Adversarial-resilience testing.** No red-team exercise, fuzzing campaign, or independent security audit has been performed against any layer. Implementation-level vulnerabilities in the R+2/R+3 prototypes and in `threshold-count.circom` may exist and are unenumerated.
- **Agent-runtime defenses.** Goal hijacking, tool misuse, and memory/context poisoning are agent-runtime concerns; the R-Series is an accountability layer and does not address them preventively.
- **Trusted-time.** No layer provides authoritative timestamps; all timestamps are issuer-asserted.

---

## 8. Residual Risk Summary

| # | Risk | Layer(s) | Mitigation today | Residual severity |
|---|------|----------|------------------|-------------------|
| 1 | Malicious signer mints false-but-valid receipts | R+2 | Non-repudiable attribution; no truth check | **High** |
| 2 | Receipt omission / selective non-disclosure | R+2/R+3 | None — inclusion proven, completeness not | **High** |
| 3 | Trusted-setup toxic waste (v0.1, family+internal cohort) | R+4 | 1-of-N honesty assumed; weak independence | **High** |
| 4 | Federation Byzantine faults | Federation | Multi-node prototype runs; production-grade BFT not implemented | **Medium-High** |
| 5 | Key compromise → forged receipts/bundles | R+2/R+3 | On-chain revoke-and-rotate; no auto-detection | **Medium-High** |
| 6 | Circuit soundness bug in `threshold-count.circom` | R+4 | Unaudited; assumed correct | **Medium-High** |
| 7 | Replay of stale receipt/bundle/proof | All | Relying-party freshness checks required | **Medium** |
| 8 | Anchor spoofing | R+3 | Sender+root binding if verifier enforces it | **Medium** |
| 9 | Composition: valid proof over dishonest inputs | R+4 | None — inherits R+2/R+3 weaknesses | **Medium** |
| 10 | Canonicalization divergence | R+3 | RFC 8785 assumed; no conformance suite | **Medium** |
| 11 | Timestamp ambiguity / backdating | R+2 | Plausibility check only; advisory | **Medium** |
| 12 | BN254 sub-128-bit security margin | R+4 | Adequate for prototype; migration noted | **Low-Medium** |
| 13 | Goal hijacking / tool misuse / memory poisoning | None | Out of scope — detective only at best | **Out of scope** |

**Overall posture.** The R-Series provides strong **integrity, attribution, and post-hoc auditability** for agent actions that are recorded. Its principal residual risks are **completeness** (it cannot prove nothing was withheld), the **v0.1 trusted-setup independence assumption**, and the **not-yet-production-hardened federation layer**. R+2 and R+3 remain operational prototypes; R+4 is a real cryptographic prototype; federation is a working multi-node prototype; none has been independently audited. This document should be revisited after a re-ceremony, an independent audit, and federation production-hardening.

---

## Appendix A — Phase 1 adversarial-test findings (23 May 2026)

Adversarial test suites were run against the R+2, R+3 and R+4 reference
verifiers. Results: R+2 — 9 attacks rejected, 1 gap; R+3 — 6/6 rejected;
R+4 — 10/10 rejected (mutated proofs, tampered public inputs, wrong keys).
Two residual risks were surfaced and are recorded here:

- **R+2-A · No nonce-uniqueness ledger.** The reference verifier validates a
  single receipt and one chain link, but keeps no cross-receipt nonce ledger,
  so a *replayed nonce* is not detected at the verifier level. Replay
  protection must be enforced by the issuing system. **Status:** documented
  scope boundary; candidate verifier fix on the Phase 1.5 list.
- **R+3-A · Conditional predecessor-chain check.** `verifyBundle` only checks
  `predecessor_hash` when the previous bundle is supplied; without it, a
  history fork / rollback is not detected. **Status:** documented; the fix is
  to require the predecessor (or an anchored predecessor hash) for any
  audit-grade verification.

Neither is a cryptographic flaw — both are scope boundaries of the reference
verifier. They are tracked for Phase 1.5 (verifier hardening).

**Update (rev 1.1).** Both Phase 1.5 fixes have since been made: R+2 gained a
nonce-uniqueness ledger (`verifyChain` / `NonceLedger`) and R+3 a mandatory
predecessor-chain check (strict mode). The adversarial suites were re-run with
the fixes in place: **R+2 10/10, R+3 12/12, R+4 10/10**. A federation
multi-node adversarial/integration test (`multinode.test.ts`) was also added
and passes 13/13.
