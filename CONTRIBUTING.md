# Contributing to R+2 Open Provenance Standard

First — thank you for considering a contribution to R+2. Open standards live or die on their contributor community, and we want yours.

This document covers:
1. [What contributions are most welcome](#what-we-welcome)
2. [How to file a spec issue](#how-to-file-an-issue)
3. [How to submit a pull request](#how-to-submit-a-pr)
4. [Conformance testing for new implementations](#conformance-testing)
5. [Sectoral profile contributions](#sectoral-profiles)
6. [Code of conduct](#code-of-conduct)

---

## What we welcome

**Highest value:**
- **Conformance test cases.** Edge cases the spec doesn't yet cover, especially around RFC 8785 canonicalization corner cases.
- **Reference implementations in additional languages.** We have TypeScript (this repo); we want Python, Go, Rust, Java. Submit a PR with passing tests against the `examples/` directory.
- **Cryptographic review of the spec.** If you find a flaw in the signing flow, the canonicalization choice, the hash-chain design — say so. Loudly. Publicly. This is exactly the feedback that produces a sound standard.

**High value:**
- **Sectoral profiles.** Healthcare, finance, government, education, supply chain — each has specific `action_data` shapes and additional constraints that R+2 doesn't (and shouldn't) specify at the core level. Profiles fill that gap.
- **Bug reports against the reference verifier or reference MCP server.** With reproducible test cases.
- **Adoption guides for specific frameworks.** "Using R+2 with LangChain", "R+2 in AutoGen", "R+2 for CrewAI agents" — each is a great post and a great PR.

**Medium value:**
- **Documentation improvements.** Typos, clarifications, missing examples in the spec.
- **CI improvements.** GitHub Actions for spec linting, example validation, link checking.

**Lower value (still welcome):**
- **Logo and branding suggestions.** We have the basics; refinements welcome.
- **Translations of the spec into other languages.** Once v0.2 stabilizes, translations become valuable for non-English-speaking regulators.

---

## How to file an issue

Before opening:
- [ ] **Read the spec.** Most "bugs" turn out to be misunderstandings of the spec. We're happy to clarify the spec, but please cite the section you find ambiguous.
- [ ] **Search existing issues.** If your issue is already tracked, add `+1` and any new context to the existing thread rather than opening a duplicate.

For spec issues, include:

```markdown
**Section of spec affected:** §4 (Schema) / §5 (Crypto) / §6 (Canonical JSON) / etc.

**Type of issue:** [ ] Bug · [ ] Ambiguity · [ ] Missing feature · [ ] Editorial

**Problem statement:**
What does the spec say? What does it allow/forbid? What's wrong or unclear?

**Proposed resolution:**
What should the spec say instead? Why?

**Citations:**
RFCs, related specs, or precedents that support your proposed resolution.

**Backwards compatibility impact:**
Would your change break existing implementations of v0.1?
```

For implementation bug reports, include:
- The version (`r2-verify --version` or `mcp-server --version`)
- The exact command you ran
- The output you got vs. what you expected
- A minimal reproducing receipt JSON

---

## How to submit a PR

### Spec changes (Markdown in `spec/`)

1. **Open an issue first.** Spec changes require discussion before code. A PR with substantial spec changes that hasn't been discussed in an issue first will likely be closed.
2. **Branch from `main`** with a descriptive name: `git checkout -b spec/clarify-prev-receipt-cid-encoding`
3. **Make the change** in `spec/r2-v0.1.md` (or open `spec/r2-v0.2.md` if it's a breaking change targeting the next version).
4. **Update the changelog** in `spec/changelog.md` under the appropriate version section.
5. **Open the PR** with a description that links to the issue.

### Reference implementation changes (code in `verifier/`, `contracts/`)

1. **Verify the tests still pass:** `npm test` in `verifier/`, `forge test` in `contracts/`.
2. **Add tests for any new behavior.** PRs without tests will not be merged.
3. **Lint:** `npm run lint`.
4. **Keep PRs small.** One change per PR. Combined PRs are harder to review and easier to break.
5. **Sign your commits.** GPG-signed commits help us trust authorship.

### Example contributions (`examples/`)

New worked examples are always welcome. Each example should:
- Be a valid R+2 receipt that passes verification against the included public key
- Cover a scenario not already in `examples/`
- Have a short README explaining what it demonstrates

---

## Conformance testing

If you've built an R+2 implementation in another language, here's how to demonstrate conformance:

1. **Pass all examples in `examples/`** through your verifier. Each must produce `verified: true`.
2. **Run negative tests:** modify each example slightly (tamper action_data, change pubkey, break chain pointer) and confirm your verifier rejects them.
3. **Publish a conformance report** in your repo's README with the results.
4. **Open a PR** to this repo adding your implementation to the [list of conformant implementations](README.md).

If your implementation diverges from the spec in any way, document it explicitly. We'd rather have honest non-conformance than silently broken claims.

---

## Sectoral profiles

A sectoral profile constrains R+2 for a specific industry. Profiles live under `spec/profiles/`.

To propose a new profile:

1. **Open an issue** describing the sector, the gap R+2's base spec leaves, and the proposed constraints.
2. **Draft the profile** as `spec/profiles/r2-<sector>-v1.md` following the structure of existing profiles.
3. **Reference relevant regulations.** A health profile should cite HIPAA, GDPR Art. 9, DPDP §9; a finance profile should cite PSD2, MAS rules, RBI master directions; etc.
4. **Identify at least two anchor organizations** in the sector willing to evaluate the profile. Profiles without sectoral validation tend to drift from operational reality.
5. **Open a PR.** The DCS standards editorial group will engage the anchor organizations during review.

Approved profiles get a registered namespace at `https://dcslabs.ai/standard/profiles/<sector>` and are referenced from the main spec.

---

## Editorial process

The R+2 specification follows a transparent editorial process:

- **Public draft (v0.x):** Issues and PRs reviewed by DCS Labs editorial team, currently one person (Deepak Dudi). Acceptance threshold: technically correct + backward compatible (within minor versions) + clearly improves the spec.
- **Multi-stakeholder (v0.2+):** Once two or more standards-body adoptions have happened, the editorial group expands to include representatives from adopting organizations. Decisions become quorum-based.
- **Ratification (v1.0):** Proposed to a recognized standards body (W3C-AI WG, IETF working group, ISO/IEC, etc.). The process becomes governed by that body's rules.

Meeting notes from editorial discussions are published at [https://dcslabs.ai/standard/governance](https://dcslabs.ai/standard).

---

## Code of conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). All contributors are expected to abide by it.

In short: **be respectful, be patient, assume good faith, focus on the substance of the contribution rather than the person**.

If you experience or witness violations, contact **conduct@dcslabs.ai**. Reports are confidential.

---

## Recognition

Significant contributors are credited:
- In the spec's `acknowledgments` section
- In the changelog for each version they contributed to
- Optionally, with a memorial Agent SBT minted on Base mainnet (we'll mint these as recognition once the contributor list grows past 5)

---

## Questions

If you're not sure whether a contribution is appropriate, open an issue and ask. There are no dumb questions in an open standard — we'd rather have 10 redundant clarifications than one silently confused contributor walking away.

— DCS AI Technologies L.L.C, on behalf of the R+2 community
