# R-Series — Hardening & Reference Documentation

These documents cover the **whole R-Series trust stack** (R+2 / R+3 / R+4),
not R+4 alone. They live in the `r4-standard` repository for convenience —
it is the most actively developed R-Series repo — but their scope is the
full stack.

| Document | Scope | What it is |
|----------|-------|------------|
| `RSERIES_THREAT_MODEL.md` | R+2 / R+3 / R+4 | Formal threat model — adversary, trust and failure assumptions; mapped against the OWASP Agentic Top 10; residual-risk table; Appendix A records the Phase-1 adversarial-test findings. |
| `RSERIES_CRYPTO_ROADMAP.md` | mainly R+4 | Why Groth16/BN254, its honest limits, the PLONK → STARK → recursion migration path, and post-quantum analysis. |
| `RSERIES_TERMINOLOGY.md` | R+2 / R+3 / R+4 | Controlled vocabulary — precise definitions of *prototype*, *operational prototype*, *production*, *federated*, *mainnet*, dev vs production keys. |
| `RSERIES_BENCHMARKS.md` | R+2 / R+3 / R+4 | Measured performance numbers + a structured measurement plan for what is not yet measured. No fabricated figures. |
| `RSERIES_FEDERATION_ARCHITECTURE.md` | R+4 | The federation design — node model, manifest lifecycle, cross-issuer verification, sync, Byzantine assumptions, phased delivery plan. |
| `REPRODUCE.md` + `reproduce.sh` | R+2 / R+3 / R+4 | Reviewer reproducibility pack — how to independently re-verify each layer; `reproduce.sh` runs the off-chain R+2/R+3 checks. |

## Honest status

These are working hardening documents from the post-ceremony hardening pass.
They are accurate as of 23 May 2026. The R-Series is at: R+2 and R+3
operational prototypes; R+4 a real cryptographic prototype with a completed
**v0.1** trusted-setup ceremony (5 contributors, family + internal) and a live
Base-mainnet verifier; federation has a working multi-node prototype, with
production-hardening still ahead. Nothing here should be read as claiming
independent audit or production-grade federation — neither exists yet.
