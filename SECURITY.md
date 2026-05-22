# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.**

Email **security@dcslabs.ai** with the details. For high-severity issues affecting:

- The R+2 cryptographic primitives (Ed25519 signing, RFC 8785 canonicalization, hash-chain)
- The TRDWorkerSBT smart contract on Base mainnet
- The reference verifier or MCP server's key custody
- Any way to forge R+2 receipts or impersonate agents

...please **encrypt with our PGP key** at https://dcslabs.ai/security/pgp.txt before sending.

## What to include in a report

- Affected component (spec section, repo, contract address, npm package version)
- Steps to reproduce — minimum reproducing input + expected vs actual behavior
- Estimated severity (Critical / High / Medium / Low — we'll re-rate as needed)
- Whether you've coordinated disclosure with any other party already
- Whether you intend public disclosure and on what timeline

## Our SLA

| Severity | Examples | Initial response | Patch target |
|---|---|---|---|
| Critical | Crypto break · contract exploit · receipt forgery · unauthorized fund movement | < 4 hours | 7 days |
| High | Auth bypass · privilege escalation · key custody compromise | < 24 hours | 14 days |
| Medium | Information disclosure · CSRF on sensitive actions | < 72 hours | 30 days |
| Low | Best-practice deviations · missing security headers | < 7 days | 90 days |

## Disclosure timeline

We follow coordinated disclosure with a default **90-day embargo** from initial report to public disclosure. Negotiable for safety-critical issues (longer if needed for fix, shorter if active exploitation observed).

After the embargo:
- A public security advisory is posted at https://dcslabs.ai/blog
- The reporter is credited (or anonymous, per their preference)
- A new release of the affected component is shipped with the fix

## What we promise reporters

- We will respond within the SLA above
- We will keep you informed of progress as we triage and fix
- We will give you credit in the public advisory (unless you prefer anonymity)
- We will not pursue legal action against good-faith reporters
- We will not threaten you for reporting in compliance with this policy

## What we ask reporters

- Don't access, modify, or destroy data that doesn't belong to you
- Don't perform testing that could degrade service for other users
- Don't attempt social engineering against our team
- Don't publicly disclose before we've had a reasonable chance to fix
- Don't extort us — reports made in good faith are welcome and rewarded; reports paired with threats are not, and will be reported to law enforcement

## Scope

In scope for coordinated disclosure:

- **R+2 Open Provenance Standard** spec (this repo, `spec/`)
- **TRDWorkerSBT contract** at `0xbDd1f5fC349D9a8EfCEb07Edbd491233b2540f5F` on Base mainnet (source in `contracts/`)
- **@trdnetwork/r2-verify** (verifier code in `verifier/` — also at https://github.com/DCS-LabsAI/r2-verify)
- **@trdnetwork/mcp-server** (separate repo at https://github.com/TRDnetwork/trd-mcp-server)
- **Sovereign Memory API** at api.dcslabs.ai/api/memory/*
- **Agent Treasury / Settlement** at api.dcslabs.ai/api/economy/*
- **Production web surfaces** dcsai.ai, dcslabs.ai, api.dcslabs.ai

Out of scope:

- Third-party services we don't operate (Cloudflare, Render, Supabase, OpenAI, Base mainnet itself)
- Social engineering against our staff
- Physical security of upstream infrastructure
- Denial-of-service via volumetric attacks
- Findings from automated scanners without manual validation

## Bounty

We don't currently operate a paid bug bounty (pre-seed solo founder). However, we credit publicly with consent and may offer a memorial Agent SBT minted in your honor on Base mainnet. We plan to launch a HackerOne / Immunefi paid program after closing our pre-seed round — that announcement will appear at https://dcslabs.ai/security.

## Contact

- security@dcslabs.ai · security@dcsai.ai
- PGP: https://dcslabs.ai/security/pgp.txt
