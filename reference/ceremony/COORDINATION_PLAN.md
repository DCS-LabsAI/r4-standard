# R+4 Trusted-Setup Ceremony — Coordination Plan

Companion to `CEREMONY.md` (the *how*). This is the *who, when, and
done-criteria* — the operational plan that turns the runbook into a dated
event. Target window: **Q3 2026**.

DCS Labs is the **coordinator**. The coordinator never holds the only secret —
the random beacon (step 6) and ≥5 independent contributors guarantee that.

---

## 1 · Contributor roster

The spec requires **≥5 independent contributors**. "Independent" is the whole
point — if all five collude, the toxic waste is recoverable. Fill these five
slots with parties whose interests and infrastructure do **not** overlap.

| Slot | Profile | Independence requirement | Name |
|------|---------|--------------------------|------|
| C1 | DCS Labs core | the coordinator's own contribution | `[TBD]` |
| C2 | External engineer / advisor | not employed by DCS; own hardware | `[TBD]` |
| C3 | Standards-body or academic contact | different org, different country | `[TBD]` |
| C4 | Community / OSS contributor | recruited via the public call | `[TBD]` |
| C5 | Pilot customer or partner | commercial counterparty, not staff | `[TBD]` |
| C6+ | Optional extra community contributors | the more the stronger | `[TBD]` |

Selection criteria for every contributor: (a) a real GitHub identity to sign
the attestation, (b) a machine they can wipe afterwards, (c) no shared
hosting/CI with another contributor. Aim to over-recruit — 6–8 confirmed so a
drop-out doesn't stall the chain.

> Names are deliberately left `[TBD]` — choosing real people is a founder
> decision, not something to auto-fill. Lock the roster before day 0.

---

## 2 · Prerequisites (before day 0)

- [ ] Circuit compiled on the build machine — `./build.sh dev` succeeds, so
      `threshold-count.r1cs` exists (see `COMPILE_RUNBOOK.md`).
- [ ] Phase 1 ptau chosen and verified — the circuit is **1,197,221
      constraints**, so use a **power-22** Powers-of-Tau (Hermez
      `powersOfTau28_hez_final_22`); `snarkjs powersoftau verify` prints
      `Powers of Tau OK`; placed at `ceremony/pot22_final.ptau`.
- [ ] `phase2_0000.zkey` initialised — `snarkjs groth16 setup
      artifacts/threshold-count.r1cs ceremony/pot22_final.ptau
      ceremony/phase2_0000.zkey` (this is the file contributor C1 receives).
- [ ] Public ceremony page drafted (circuit source, `.r1cs`, `CEREMONY.md`,
      `phase2_0000.zkey`, this plan).
- [ ] ≥5 contributors confirmed in writing with target contribution dates.
- [ ] Beacon source pre-announced (see §4) — committed *before* contributions
      start so it cannot be cherry-picked.

---

## 3 · Schedule (16-day window)

| Day | Date (set on lock) | Action | Owner |
|-----|--------------------|--------|-------|
| 0   | `[TBD]` | Announce publicly; open contribution window; publish `phase2_0000.zkey` | Coordinator |
| 1–3 | | C1 → C2 contribute (chain in order) | C1, C2 |
| 4–7 | | C3 → C4 contribute | C3, C4 |
| 8–12| | C5 (+ any C6+) contribute | C5+ |
| 13–14| | Buffer for slips / re-recruit if a contributor drops | Coordinator |
| 15  | | Chain all contributions, apply the random beacon, verify | Coordinator |
| 16  | | Publish transcript + attestations; register `vk_hash`; anchor on Base | Coordinator |

Each contributor receives the previous contributor's `.zkey`, runs
`contribute.sh` on an air-gapped machine, returns their `.zkey` + contribution
hash, then wipes the machine. The coordinator verifies each returned `.zkey`
chains onto the previous one before passing it to the next contributor.

---

## 4 · Random beacon

The final word must not be the coordinator's. Finalise with a public,
unpredictable value fixed *after* all contributions are in:

- **Source:** the Bitcoin block hash at a pre-announced future height (pick a
  height ~1 day after day 14). Announce the exact height on day 0.
- **Apply:** `snarkjs zkey beacon phase2_N.zkey phase2_final.zkey <hash> 10`
- Record the block height, hash, and timestamp in the transcript.

---

## 5 · Attestation (each contributor publishes this)

```
R+4 Phase 2 ceremony — contribution attestation
  contributor : <name / GitHub handle>
  position    : <n> of <total>
  input zkey  : <sha256 of the .zkey received>
  output zkey : <sha256 of the .zkey produced>
  contribution hash : <the 12-line hash printed by snarkjs zkey contribute>
  machine     : <fresh OS, air-gapped — confirmed wiped: yes>
  date        : <UTC>
  signed      : <GitHub-verified commit or signed message>
```

The coordinator collects all five (+) attestations and publishes them
alongside the transcript.

---

## 6 · Done criteria (go / no-go gate)

R+4 production trust is **achieved** only when all of these hold:

- [ ] ≥5 independent contributors, each with a published attestation.
- [ ] `snarkjs zkey verify threshold-count.r1cs pot22_final.ptau phase2_final.zkey`
      prints `ZKey Ok`.
- [ ] Random beacon applied and its source documented in the transcript.
- [ ] `phase2_final.zkey`, `verification_key.json`, full transcript, and all
      attestations published at a public, permanent URL.
- [ ] `vk_hash` registered in the R+4 registry and anchored on Base mainnet
      (CEREMONY.md §6.5 / step 7).
- [ ] `./build.sh prod` run against the ceremony output; the resulting prover
      generates a proof that `verifier/verify.ts` accepts.

Until every box is checked, R+4 runs on **dev keys** and must be described that
way — single-contributor, fine for testing and the reference verifier, not
production-trustless. Do not present dev-key proofs as ceremony-backed.

---

## 7 · After the ceremony

- Flip R+4's status from "dev keys" to "production keys — ceremony N
  contributors, <date>" on the roadmap and `STATUS.md`.
- Publish a short ceremony report (contributors, beacon, vk_hash, anchor tx).
- Keep `phase2_final.zkey` + `pot22_final.ptau` in `ceremony/`; archive the
  per-contributor intermediate `.zkey`s with the transcript.
