# R+4 Federation Module — Reference Implementation

A **single-process reference implementation** of the R+4 federation protocol:
the federation manifest (R+4 spec §8) and the cross-issuer verification
algorithm (R+4 spec §8.2).

## What this module is

The federation layer answers one question: *should issuer B accept a
zero-knowledge proof produced by issuer A?* It does this with:

- **`manifest.ts`** — a canonicalised (RFC-8785), Ed25519-signed,
  hash-chained **federation manifest**: the list of member issuers and the
  circuits (verifying keys) the federation accepts. Build / sign / verify /
  update are all here.
- **`cross-issuer.ts`** — the **§8.2 cross-issuer verification algorithm**.
  Given a proof and a signed manifest it runs five steps, each a clean
  rejection on failure:
  1. the federation manifest signature is valid
  2. the proof's `issuer_id` is a manifest member
  3. the proof's `circuit_id` is an accepted circuit
  4. the resolved verifying key hashes to the manifest's registered `vk_hash`
  5. the **Groth16 pairing check** passes
- **`multi-issuer-sim.ts`** — an in-process simulation of three issuer
  organisations sharing one federation manifest.
- **`fixtures/`** — a **real dev-key** Groth16 `verification_key.json` and a
  matching `proof.json`, used so step 5 above can run for real.

The cryptography is real (Ed25519 signing, SHA-256 vk hashing, Groth16
pairing). The network is simulated — every "issuer" is just a keypair in
local memory and the manifest is a plain object shared by reference.

## Status: v0.1 → v0.2 → v1.0

| Version | Status | Scope |
|---|---|---|
| **v0.1** | done | Manifest build/sign/verify/update + §8.2 steps 1–4. Step 5 ran against a **stub** verifying key, so it could *reach* but never *pass* the Groth16 check. |
| **v0.2** | **this release (partial)** | **End-to-end cross-issuer verification working in-process.** A real dev-key Groth16 verifying key and proof are wired in, so all five §8.2 steps execute and step 5 returns `true` for a genuine proof and `false` for a mutated one. Plus a 3-issuer single-process simulation. |
| **v1.0** | future | Real distributed **multi-node** networking, transport, live manifest **gossip / sync**, revocation propagation, persistence + replay protection across restarts, key-rotation ceremony, and **Byzantine fault tolerance / consensus** among issuers. |

### What v0.2 explicitly does NOT do (honest limitations)

This remains a single-process reference. **Not** implemented:

- real distributed multi-node operation, networking, or transport
- gossip-based manifest synchronisation or revocation propagation
- Byzantine fault tolerance or consensus among issuers
- persistence or replay protection across process restarts
- a key-rotation ceremony

The verifying key in `fixtures/verification_key.json` is a **DEVELOPMENT
key**. The production-ceremony verifying key would be exported separately
from `phase2_final.zkey`; the §8.2 algorithm is unchanged by that swap.

> Note: `fixtures/proof.json` carries a `vk_hash` field computed by an older
> pipeline using a different hashing convention than this module's
> RFC-8785 + SHA-256 `vkHash()`. The v0.2 tests therefore register the
> manifest with the hash this module actually computes over the real vk and
> do not depend on the proof's stale embedded field. Step 4 still fully runs.

## How to run the tests

From the reference root (`r4-standard/reference/`):

```bash
npm install            # once, if node_modules is absent

# v0.1 federation-layer suite — manifest + §8.2 steps 1–4, 5 attacks
npx tsx federation/test/federation.test.ts

# v0.2 end-to-end suite — all five §8.2 steps, REAL Groth16 verify
npx tsx federation/test/cross-issuer-e2e.test.ts

# 3-issuer single-process simulation (runnable demo)
npx tsx federation/multi-issuer-sim.ts
```

Or via npm scripts:

```bash
npm run test:federation       # v0.1 suite
npm run test:federation:e2e   # v0.2 end-to-end suite
npm run sim:federation        # multi-issuer simulation demo
```

### Observed v0.2 results

- `cross-issuer-e2e.test.ts` — 4/4 checks pass: the genuine dev-key proof is
  `verified` (real `groth16.verify` returns `true`); a proof with a mutated
  public input and a proof with a tampered `pi_a` point are both rejected at
  step 5 (`groth16_invalid: pairing check failed`).
- `multi-issuer-sim.ts` — a proof from a member issuer is `ACCEPTED`
  (`verified`); the same proof attributed to a non-member issuer is
  `REJECTED` (`issuer_not_member`).
