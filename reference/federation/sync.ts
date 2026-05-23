// ===========================================================================
// R+4 "Federation Protocol" — manifest SYNC + REVOCATION simulation
// R+4 spec §8 (Multi-Issuer Federated Zero-Knowledge Verification)
// ===========================================================================
//
// SCOPE / HONESTY NOTICE
// ----------------------
// This is a SINGLE-PROCESS SIMULATION of the federation manifest *sync
// protocol*. It models a set of federation nodes as plain in-memory objects,
// each holding its own current manifest, and simulates "propagation" by
// passing a manifest to every node and letting each node independently decide
// whether to adopt it.
//
// What this module DOES validate, and validates correctly:
//   - CONVERGENCE: honest nodes that receive a newer, validly-signed,
//     correctly-chained manifest all adopt it and end on the same version.
//   - FORK / BYZANTINE REJECTION at the manifest level: a node only adopts a
//     manifest if verifyManifest() passes AND version is strictly higher AND
//     predecessor_hash chains to the node's current manifest. A forged
//     signature, a same-version fork, or a broken predecessor chain is
//     rejected — the node keeps its prior manifest.
//   - STALE-NODE CATCH-UP: a node left behind on an old version adopts the
//     current manifest on the next propagation round.
//   - REVOCATION PROPAGATION: a manifest version N+1 that removes a member
//     issuer, once propagated, causes every honest node to stop accepting
//     that issuer's cross-issuer proofs.
//
// What this is NOT — explicit OUT OF SCOPE (still v1.0 future work):
//   - it is NOT a deployed multi-node network. There are no sockets, no
//     transport, no gossip protocol — `propagate()` is a synchronous loop.
//   - no liveness, partition, or network-failure handling: every node is
//     assumed reachable on every round.
//   - no consensus / leader election among nodes; manifests are still minted
//     by a single trusted federation authority key.
//   - no anti-entropy, no retry/backoff, no message ordering guarantees.
//   - no persistence or replay protection across process restarts.
//
// This advances the federation reference implementation from v0.2 toward
// v1.0 by implementing the convergence / fork-rejection / revocation LOGIC.
// It does NOT complete v1.0. The cryptography (Ed25519, SHA-256 hash chain)
// is real; the network is simulated. See README.md for the version roadmap.
// ===========================================================================

import {
  verifyManifest,
  manifestHash,
  type FederationManifest,
  type SignedManifest,
} from "./manifest.js";
import {
  verifyCrossIssuerProof,
  type CrossIssuerResult,
  type GetVerifyingKey,
  type R4ProofObject,
} from "./cross-issuer.js";

// ── a federation node ────────────────────────────────────────────────────────

/**
 * One federation node. In a real deployment this would be a separate process
 * with its own network identity and storage; here it is an in-memory object.
 *
 * A node holds:
 *   - the federation-authority public key it trusts (out-of-band bootstrap),
 *   - its CURRENT signed manifest (the latest one it has accepted),
 *   - an append-only adoption log for inspection / debugging.
 */
export interface FederationNode {
  node_id: string;
  /** Authority key this node trusts; manifests must verify against it. */
  authorityPk: string;
  /** The newest signed manifest this node has accepted. */
  current: SignedManifest;
  /** Human-readable record of every adopt / reject decision. */
  log: string[];
}

/**
 * Create a federation node bootstrapped at a genesis (or any starting)
 * manifest. The starting manifest is assumed already trusted (out-of-band).
 */
export function makeNode(
  node_id: string,
  authorityPk: string,
  genesis: SignedManifest,
): FederationNode {
  return {
    node_id,
    authorityPk,
    current: genesis,
    log: [`bootstrapped at v${genesis.version}`],
  };
}

// ── adoption decision (the core convergence / fork-rejection rule) ───────────

export interface AdoptDecision {
  adopted: boolean;
  /** Machine-readable outcome code. */
  reason: string;
  /** Node version before this decision. */
  fromVersion: number;
  /** Node version after this decision (unchanged if not adopted). */
  toVersion: number;
}

/**
 * Decide whether `node` should adopt `candidate`, and apply it if so.
 *
 * An honest node adopts `candidate` ONLY IF ALL of the following hold:
 *   1. verifyManifest(candidate, node.authorityPk) passes — structural
 *      sanity + a valid Ed25519 signature by the federation authority. This
 *      rejects forged-signature and malformed/tampered manifests.
 *   2. candidate.version is STRICTLY GREATER than node.current.version. This
 *      rejects stale replays and same-version forks (two different manifests
 *      claiming the same version number).
 *   3. candidate.predecessor_hash chains correctly. The candidate must be
 *      reachable from the node's current manifest by walking version numbers
 *      down the predecessor chain — at minimum, a +1 successor must carry
 *      predecessor_hash === manifestHash(node.current). For multi-step jumps
 *      (stale-node catch-up) the caller supplies the intermediate manifests
 *      via `chain` so the node can verify each link.
 *
 * If any check fails the node KEEPS its current manifest unchanged. This is
 * the Byzantine-resistance property at the manifest layer: a malicious
 * manifest cannot displace an honest node's state.
 *
 * @param node      the node making the decision (mutated on adoption).
 * @param candidate the manifest being offered.
 * @param chain     optional ordered list of every signed manifest from
 *                   node.current's successor up to `candidate` inclusive,
 *                   used to validate a multi-version jump link-by-link.
 *                   When omitted, only a direct +1 successor is accepted.
 */
export function adopt(
  node: FederationNode,
  candidate: SignedManifest,
  chain?: SignedManifest[],
): AdoptDecision {
  const fromVersion = node.current.version;
  const fail = (reason: string): AdoptDecision => {
    node.log.push(`REJECT v${candidate.version}: ${reason}`);
    return { adopted: false, reason, fromVersion, toVersion: fromVersion };
  };

  // ── check 1: signature + structural validity ──────────────────────────
  const vr = verifyManifest(candidate, node.authorityPk);
  if (!vr.ok) return fail(`manifest_invalid: ${vr.reason ?? "unknown"}`);

  // candidate must belong to the same federation the node is part of.
  if (candidate.federation_id !== node.current.federation_id) {
    return fail(
      `wrong_federation: ${candidate.federation_id} != ${node.current.federation_id}`,
    );
  }

  // ── check 2: strictly newer version ───────────────────────────────────
  if (candidate.version <= node.current.version) {
    // covers both stale replays (<) and same-version forks (===).
    return fail(
      candidate.version === node.current.version
        ? `fork_or_replay: same version v${candidate.version} as current`
        : `stale: v${candidate.version} <= current v${node.current.version}`,
    );
  }

  // ── check 3: predecessor_hash chains back to the node's current state ──
  // Build the ordered link path the candidate claims. For a direct +1
  // successor no `chain` is needed. For a multi-version jump the caller
  // supplies every intermediate signed manifest so each link is checked.
  let path: SignedManifest[];
  if (candidate.version === node.current.version + 1) {
    path = [candidate];
  } else {
    if (!chain || chain.length === 0) {
      return fail(
        `chain_unavailable: cannot verify multi-version jump v` +
          `${node.current.version}->v${candidate.version} without intermediates`,
      );
    }
    path = chain;
    // the supplied chain must end exactly at `candidate`.
    const last = path[path.length - 1];
    if (last.version !== candidate.version ||
        manifestHash(last) !== manifestHash(candidate)) {
      return fail("chain_mismatch: supplied chain does not end at candidate");
    }
  }

  // walk the path: each manifest must be a valid, authority-signed +1
  // successor whose predecessor_hash equals the hash of the previous link.
  let prev: SignedManifest = node.current;
  for (const link of path) {
    const lvr = verifyManifest(link, node.authorityPk);
    if (!lvr.ok) {
      return fail(`chain_link_invalid v${link.version}: ${lvr.reason}`);
    }
    if (link.version !== prev.version + 1) {
      return fail(
        `chain_gap: v${link.version} does not follow v${prev.version}`,
      );
    }
    if (link.predecessor_hash !== manifestHash(prev)) {
      return fail(
        `broken_chain: v${link.version}.predecessor_hash != hash(v${prev.version})`,
      );
    }
    prev = link;
  }

  // ── all checks passed: adopt ──────────────────────────────────────────
  node.current = candidate;
  node.log.push(`ADOPT v${fromVersion} -> v${candidate.version}`);
  return {
    adopted: true,
    reason: "adopted",
    fromVersion,
    toVersion: candidate.version,
  };
}

// ── propagation ──────────────────────────────────────────────────────────────

export interface PropagateResult {
  /** Per-node adoption decision, keyed by node_id. */
  decisions: Record<string, AdoptDecision>;
  /** true iff every node ended on the same manifest version. */
  converged: boolean;
  /** The version every node converged on, or null if not converged. */
  convergedVersion: number | null;
}

/**
 * Distribute a newly-signed manifest to every node and let each node
 * independently decide whether to adopt it (see `adopt`).
 *
 * SIMULATION NOTE: this is a synchronous in-process loop. There is no
 * transport, no message loss, no ordering ambiguity, and every node is
 * assumed reachable. A real gossip/sync layer (v1.0) would replace this loop
 * with networked, partial, retried, out-of-order delivery.
 *
 * @param nodes        the federation nodes (mutated in place on adoption).
 * @param newManifest  the manifest being propagated.
 * @param chain        optional intermediates for nodes that need a
 *                      multi-version catch-up (see `adopt`).
 */
export function propagate(
  nodes: FederationNode[],
  newManifest: SignedManifest,
  chain?: SignedManifest[],
): PropagateResult {
  const decisions: Record<string, AdoptDecision> = {};
  for (const node of nodes) {
    decisions[node.node_id] = adopt(node, newManifest, chain);
  }
  const versions = new Set(nodes.map((n) => n.current.version));
  const converged = versions.size === 1;
  return {
    decisions,
    converged,
    convergedVersion: converged ? [...versions][0] : null,
  };
}

// ── revocation ───────────────────────────────────────────────────────────────

export interface RevokeResult {
  /** The signed manifest with the issuer removed. */
  manifest: SignedManifest;
  /** The issuer_id that was revoked. */
  revoked: string;
}

/**
 * Produce the next manifest version (prev.version + 1) that REMOVES a member
 * issuer, correctly chained and re-signed. This is just `updateManifest` with
 * a `removeMembers` change, surfaced under a revocation-specific name so the
 * intent is explicit at call sites.
 *
 * Once this manifest is `propagate`d, every honest node's `current` manifest
 * no longer lists the revoked issuer, so `verifyCrossIssuerProof` against any
 * honest node's manifest returns `issuer_not_member` for that issuer — i.e.
 * revocation has propagated.
 *
 * Implemented via dynamic import of updateManifest to keep this module's
 * surface focused on the sync/revocation logic.
 *
 * @param prev      a signed predecessor manifest (the current federation state).
 * @param issuerId  the member issuer_id to revoke.
 * @param privKey   the federation-authority Ed25519 private key.
 * @param keyId     identifier recorded in the new manifest's signature.
 */
export async function revoke(
  prev: SignedManifest,
  issuerId: string,
  privKey: Uint8Array | string,
  keyId?: string,
): Promise<RevokeResult> {
  if (!prev.members.some((m) => m.issuer_id === issuerId)) {
    throw new Error(`cannot revoke non-member issuer: ${issuerId}`);
  }
  const { updateManifest } = await import("./manifest.js");
  const manifest = updateManifest(
    prev,
    { removeMembers: [issuerId] },
    privKey,
    keyId,
  );
  return { manifest, revoked: issuerId };
}

/**
 * Convenience: ask whether a given issuer is still accepted by a node's
 * CURRENT manifest, by running the §8.2 cross-issuer check for a proof from
 * that issuer. After a revocation has propagated this returns a result whose
 * `reason` is `issuer_not_member` for the revoked issuer.
 */
export function issuerAcceptedBy(
  node: FederationNode,
  proof: R4ProofObject,
  getVerifyingKey: GetVerifyingKey,
): Promise<CrossIssuerResult> {
  return verifyCrossIssuerProof(
    proof,
    node.current,
    getVerifyingKey,
    node.authorityPk,
  );
}
