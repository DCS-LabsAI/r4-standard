# R-Series Performance Benchmarks

**Component:** DCS Labs "R-Series" AI-agent trust stack
**Document type:** Performance benchmarks and measurement plan
**Status:** Partial — measured results plus a forward measurement plan
**Last updated:** 2026-05-23

---

## 1. Purpose

Trust infrastructure is only credible if its performance characteristics are
known, documented, and reproducible. Operators integrating the R-Series stack
need to know how long it takes to sign a receipt, build a bundle, generate and
verify a proof, and anchor state on-chain — because those numbers determine
whether the stack fits inside their latency budget, their hardware budget, and
their cost model. Vague or aspirational performance claims undermine the very
property the R-Series exists to provide: verifiable, honest accounting of what
an AI agent did.

This document is therefore deliberately split into two parts:

- **Measured results** — a small set of numbers that have actually been
  observed in testing. These are stated as measured, with the method of
  measurement noted.
- **A measurement plan** — the larger set of metrics that have **not** yet been
  measured. These are presented as structured "to measure" items, with no
  values attached. No placeholder number in this document should be read as an
  estimate, a target SLA, or a prediction.

This is an honest, partial benchmark. It should be treated as a snapshot of
what is known today, and as a work plan for closing the remaining gaps.

---

## 2. Measured results

The following numbers have been observed in development or scale testing. Each
is labelled with how it was obtained and under what conditions. Where a number
is a known mathematical property of the underlying scheme rather than a DCS
measurement, that is stated explicitly.

Hardware note: the rows added on **23 May 2026** were measured on the
**workspace VM** (a shared Linux VM, 4 vCPU, ~3.9 GB RAM). These are not
production-hardware figures; a production server profile (see §4) will differ,
typically favourably for CPU-bound work. Each such row is tagged
*(measured: 23 May 2026, workspace VM)*.

| Metric | Layer | Value | How obtained |
|---|---|---|---|
| Groth16 proof verification time | R+4 | ~144 ms | Measured off-chain using development keys. Not a production-key or production-hardware figure. |
| Circuit size | R+4 | 1,197,221 R1CS constraints | Reported by the compiler for `threshold-count.circom` (Groth16 over BN254). |
| Proof size | R+4 | ~200 bytes | Known constant-size property of Groth16 over BN254 — proof size does not grow with circuit size. Stated as a scheme property, not a DCS measurement. |
| On-chain `verifyProof` gas cost | R+4 | ~250,000 gas (approximate / typical) | Typical cost of a Groth16 BN254 verifier on the EVM. Stated as an approximate known property of the verifier pattern, not a DCS-measured figure on a specific deployment. |
| Verifier scale test | R+2 | Passed against a 10,000-receipt chain | Scale test executed against a 10,000-receipt chain; the test runbook documents throughput on the order of 1,000+ receipts/second verified. Stated as documented in the scale test, approximate. |
| Phase-2 ceremony per-contribution time | R+4 | ~10–60 minutes per contribution (observed range) | Observed during the Phase-2 trusted setup ceremony on a power-22 Powers-of-Tau, running on a normal laptop. Stated as an observed range, not a precise benchmark. |
| Receipt sign latency | R+2 | ~0.20 ms per receipt (mean) | *(measured: 23 May 2026, workspace VM)* Derived from `npm run scale`: building a 10,000-receipt signed chain (Ed25519 sign + RFC 8785 canonicalize + SHA-256 CID) took 2,039 ms → ~4,900 receipts/s. Sign is the dominant cost in the build loop. Warm run, single sample of 10k operations; p50/p95 tail not yet isolated. |
| Receipt verify latency (single) | R+2 | ~0.857 ms per receipt | *(measured: 23 May 2026, workspace VM)* From `npm run scale`: full §9 verification (schema + Ed25519 verify + chain-pointer SHA-256) of a 10,000-receipt chain took 8,571 ms → 1,167 receipts/s, i.e. 0.857 ms/receipt. Warm run, single 10k-receipt sample; this confirms the runbook's "1,000+ receipts/s". |
| Bundle build time | R+3 | 10: 0.59 ms · 100: 1.09 ms · 1k: 6.06 ms · 10k: 59.9 ms (p50) | *(measured: 23 May 2026, workspace VM)* Throwaway tsx timing script over `buildBundle` (SHA-256 binary Merkle tree + one Ed25519 header signature) on synthetic receipt sets. 30 runs each (10 runs at n=10k), warm. p95 at n=10k ~102 ms. Scales roughly linearly in receipt count. |
| Merkle inclusion-proof generation time | R+3 | ~0.004–0.015 ms per proof (p50, n=10 to 10k) | *(measured: 23 May 2026, workspace VM)* `proveInclusion` over a pre-built tree, 200 proofs per size. Sub-millisecond and O(log n); p50 0.0042 ms at n=10, 0.0145 ms at n=10k. |
| Merkle inclusion-proof verification time | R+3 | ~0.009–0.025 ms per proof (p50, n=10 to 10k) | *(measured: 23 May 2026, workspace VM)* `verifyInclusion` against a known root, 200 proofs per size. p50 0.0093 ms at n=10, 0.0245 ms at n=10k; p95 ≤ 0.028 ms. |
| Proof generation time (one proof) — **upper bound** | R+4 | ≈16 min 37 s wall-clock (≈997 s) | *(measured: 23 May 2026, founder's Mac, **development keys**)* One `npm run prove` over `example-bundle.json` for `threshold-count.circom` (1,197,221 constraints): `141.6 s user + 22.9 s system` CPU, **16:37.28 total**. Critically, CPU utilisation was only **~16%** — the run was **memory/IO-bound**, not compute-bound: loading the ~581 MB proving key plus witness generation dominated wall-clock. This is therefore an **upper bound**, not a representative proving figure; a proving profile with adequate RAM headroom would very likely be far faster. The same run earlier OOM-killed on the 3.9 GB workspace VM. |

**Notes on interpretation:**

- The ~144 ms verification figure was measured with **development keys** and is
  not a substitute for a production-key, production-hardware measurement.
- The ~250,000 gas figure is a *typical* cost for the Groth16 BN254 verifier
  pattern on the EVM; the exact cost on a given chain and verifier
  implementation must be measured per deployment.
- The R+2 scale-test throughput ("1,000+ receipts/second") is what the test
  runbook documents; it is reproduced here as documented, not re-derived.

---

## 3. Measurement plan

The metrics below are **not yet measured**. They are listed here as a work
plan. No value is given for any of them. Status for every row is **TO
MEASURE**.

Three R+2/R+3 rows previously listed here (receipt sign latency, receipt verify
latency, bundle build time, Merkle inclusion-proof generation/verification) were
measured on **23 May 2026** on the workspace VM and have been promoted into §2.
What remains below is genuinely unmeasured.

| Metric | Layer | How to measure | Target hardware profile | Status |
|---|---|---|---|---|
| Receipt sign latency — p50/p95/p99 in isolation | R+2 | The §2 figure is a mean derived from a single 10k-receipt scale run. Still to do: time the signing operation in isolation and report median and tail (p50/p95/p99) over ≥30 repeats. | Reference server profile (see §4). | TO MEASURE |
| Bundle build/verify — p99 tail on reference hardware | R+3 | §2 records p50/p95 from the workspace VM. Still to do: repeat on the reference server profile and report p99. | Reference server profile. | TO MEASURE |
| Proof generation time (production scale) | R+4 | Time full witness generation + Groth16 proving for `threshold-count.circom` using **production keys**, at production input sizes. | Reference proving profile — high-core-count CPU with sufficient RAM; record exact spec. | PARTIALLY MEASURED — *a first run is now in §2: ≈16 min 37 s on the founder's Mac with development keys. That run was memory-bound (~16% CPU), so it is an upper bound only. Still TO DO: a run on a named reference proving profile (recorded high-RAM spec) with production (ceremony) keys, to obtain a representative figure. The earlier 23 May attempt OOM-killed on the 3.9 GB workspace VM.* |
| Proof verification time (reproduced) | R+4 | Run `npm run verify` against a freshly generated proof. | Reference client profile. | TO MEASURE — *could not run on 23 May 2026: no proof artifact was produced because proof generation was OOM-killed (see row above). The existing ~144 ms §2 figure stands as the only verification measurement.* |
| Proof generation memory footprint | R+4 | Record peak resident memory during witness generation and proving. | Same proving profile as above. | TO MEASURE — *partial observation 23 May 2026: peak RSS reached ~3.6 GB before the OOM kill on the workspace VM, so true peak is higher and unmeasured. Needs a profile with adequate RAM.* |
| End-to-end throughput | R+2 / R+3 / R+4 | Drive the full pipeline (sign -> bundle -> prove -> verify) under sustained load; report receipts/second sustained and the bottleneck stage. | Reference server + proving profile. | TO MEASURE |
| Steady-state memory footprint | R+2 / R+3 | Record resident memory of the signing/bundling services under sustained load. | Reference server profile. | TO MEASURE |
| On-chain anchor latency | R+4 | Measure wall-clock time from anchor-transaction submission to confirmation, on the target chain(s); separate submission latency from confirmation latency. | Target chain(s); record chain, network conditions, and confirmation depth. | TO MEASURE |
| On-chain anchor cost | R+4 | Measure gas used by the anchor transaction (distinct from `verifyProof` gas) on each target chain. | Target chain(s). | TO MEASURE |

If any of these is measured in future, it should be promoted into the
"Measured results" table in §2 with its method noted, and removed from this
plan.

---

## 4. Methodology

For future benchmarks to be meaningful, comparable across releases, and
reproducible by third parties, every measurement must follow the same
discipline.

**Fixed hardware profiles.** Define and pin a small number of named hardware
profiles, and run every benchmark on a named profile. At minimum:

- *Reference server profile* — for signing, bundling, and verification
  services.
- *Reference proving profile* — for R+4 witness generation and Groth16
  proving (proving is CPU- and memory-intensive; it should not share a profile
  with the lightweight services).
- *Reference client profile* — for client-side proof verification.

For each profile, record CPU model and core count, RAM, storage type, OS and
kernel version, and the version of every relevant toolchain component (circom,
snarkjs or equivalent prover, Node/runtime versions). A benchmark result is
only valid when accompanied by the profile it ran on.

**Warm vs cold runs.** Report cold-start and warm-state numbers separately. A
cold run includes one-time costs (key loading, JIT warm-up, cache population);
a warm run reflects steady-state operation. Discard a fixed number of warm-up
iterations before recording warm runs, and state how many were discarded.

**Dataset sizes.** Use a fixed, documented set of dataset sizes so results are
comparable across runs and releases. For receipt-chain and bundle metrics,
sweep at least 10, 100, 1,000, and 10,000 receipts. The existing R+2 scale test
(10,000-receipt chain) should remain a fixed point so its result stays
comparable over time.

**Repeat counts and statistics.** Run each measurement enough times to produce
stable statistics — a minimum of 30 repeats for latency metrics, more for
high-variance operations. Report median (p50) and tail percentiles (p95, p99),
not just the mean, and report the standard deviation or inter-quartile range.
For throughput, report sustained throughput over a fixed-duration load test,
not a peak burst.

**Production vs development keys.** Clearly label whether a proving or
verification number used development or production keys. The two are not
interchangeable, and a development-key number must never be presented as a
production result.

**Environmental controls.** Run on an otherwise-idle machine, disable CPU
frequency scaling where possible (or record the governor), and record ambient
conditions that could affect thermal throttling for long proving runs. For
on-chain measurements, record the chain, the network conditions, and the
confirmation depth used.

**Reproducibility.** Publish the benchmark scripts, the input datasets (or a
deterministic generator for them), and the exact toolchain versions alongside
any published result, so a third party can reproduce it.

---

## 5. Honest summary

**What can be claimed today:**

- R+4 Groth16 proof verification has been measured at ~144 ms off-chain using
  development keys.
- The R+4 `threshold-count.circom` circuit compiles to 1,197,221 R1CS
  constraints under Groth16 over BN254.
- R+4 proofs are ~200 bytes — a constant-size property of Groth16 over BN254.
- An on-chain Groth16 BN254 `verifyProof` call typically costs on the order of
  ~250,000 gas; this is a known property of the verifier pattern and must be
  confirmed per deployment.
- The R+2 verifier has passed a scale test against a 10,000-receipt chain, with
  the test runbook documenting throughput on the order of 1,000+
  receipts/second verified.
- The R+4 Phase-2 ceremony, on a power-22 Powers-of-Tau, showed per-contribution
  times in the observed range of ~10–60 minutes on a normal laptop.
- On the workspace VM (4 vCPU, ~3.9 GB RAM; 23 May 2026): R+2 signs a receipt in
  ~0.20 ms and verifies one with the full chain check in ~0.857 ms; R+3 builds a
  10,000-receipt bundle in ~60 ms (p50); and R+3 Merkle inclusion proofs both
  generate and verify in well under 0.03 ms each, scaling logarithmically.
- A first R+4 proof-generation run has been measured: ≈16 min 37 s wall-clock on
  the founder's Mac with development keys (23 May 2026). This is stated as an
  **upper bound** only — the run used just ~16% CPU, i.e. it was memory/IO-bound
  (loading the ~581 MB proving key), not a representative compute time.

**What is pending measurement:**

- R+2 sign/verify p50/p95/p99 tail in isolation (the workspace-VM figures are a
  mean and p50/p95 from single scale runs, not isolated tail percentiles).
- R+3 bundle build/verify p99 tail on the reference server profile.
- R+4 proof generation on a **named reference proving profile** (recorded
  high-RAM spec) with **production (ceremony) keys**, plus its peak-memory
  footprint. A first run is now measured — ≈16 min 37 s on the founder's Mac
  with dev keys (see §2) — but it was memory-bound (~16% CPU) and is only an
  upper bound, so a representative production figure is still outstanding.
- End-to-end pipeline throughput and the location of the bottleneck.
- Steady-state memory footprint of the signing and bundling services.
- On-chain anchor latency and anchor gas cost on target chains.

Until those items are measured under the methodology in §4, they must not be
quoted, estimated, or implied. This document will be revised as measurements
are completed and promoted from the plan in §3 into the results table in §2.
