// ===========================================================================
// R+4 "Federation Protocol" — federation manifest module
// R+4 spec §8 (Multi-Issuer Federated Zero-Knowledge Verification)
// ===========================================================================
//
// SCOPE / HONESTY NOTICE
// ----------------------
// This is a SINGLE-PROCESS REFERENCE IMPLEMENTATION of the federation
// *protocol*. It simulates multiple independent issuer organisations inside
// one Node.js process: every "member" is just an Ed25519 keypair held in
// local memory, and the manifest is a plain JSON object passed by reference.
//
// It is NOT a deployed multi-node network. The following are explicitly OUT
// OF SCOPE and remain future work:
//   - real distributed multi-node operation / networking / transport
//   - Byzantine fault tolerance and consensus among issuers
//   - live manifest synchronisation, gossip, or revocation propagation
//   - persistence, replay protection across restarts, key rotation ceremony
//
// What this module DOES give you, and gives you correctly, is the protocol
// itself: a canonicalised, Ed25519-signed, hash-chained manifest document
// plus the cross-issuer verification algorithm of §8.2. The cryptography is
// real; the network is simulated.
// ===========================================================================

import { canonicalize } from "json-canonicalize";
import { sha256 } from "@noble/hashes/sha2.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import * as ed from "@noble/ed25519";

// @noble/ed25519 v3 needs a sha512 implementation wired in for sync APIs.
ed.hashes.sha512 = (...m) => sha512(ed.etc.concatBytes(...m));

// ── types ──────────────────────────────────────────────────────────────────

export interface Member {
  issuer_id: string;
  /** Ed25519 public key, hex-encoded (64 hex chars / 32 bytes). */
  issuer_pubkey: string;
}

export interface AcceptedCircuit {
  circuit_id: string;
  /** Hash of the circuit's verifying key, e.g. "sha256:<64 hex>". */
  vk_hash: string;
}

export interface ManifestSignature {
  alg: "ed25519";
  /** Identifies which federation-authority key signed this manifest. */
  key_id: string;
  /** Ed25519 signature, hex-encoded (128 hex chars / 64 bytes). */
  sig: string;
}

export interface FederationManifest {
  federation_id: string;
  /** Monotonic integer; genesis = 1. */
  version: number;
  /** "sha256:" + 64 hex chars. Genesis = "sha256:" + 64 zeros. */
  predecessor_hash: string;
  members: Member[];
  accepted_circuits: AcceptedCircuit[];
  signature?: ManifestSignature;
}

/** Manifest with the signature field guaranteed present. */
export type SignedManifest = FederationManifest & { signature: ManifestSignature };

export const GENESIS_PREDECESSOR = "sha256:" + "0".repeat(64);

// ── helpers ──────────────────────────────────────────────────────────────────

/** Strip the signature field for canonical signing/verification. */
function unsignedView(m: FederationManifest): Omit<FederationManifest, "signature"> {
  const { signature, ...rest } = m;
  return rest;
}

/**
 * SHA-256 of the FULL canonicalised manifest (signature included).
 * This is the value a successor manifest references as predecessor_hash.
 */
export function manifestHash(m: FederationManifest): string {
  const bytes = utf8ToBytes(canonicalize(m));
  return "sha256:" + bytesToHex(sha256(bytes));
}

// ── build ──────────────────────────────────────────────────────────────────

export interface BuildManifestParams {
  federation_id: string;
  members: Member[];
  accepted_circuits: AcceptedCircuit[];
  /** Defaults: version 1, genesis predecessor_hash. */
  version?: number;
  predecessor_hash?: string;
}

/**
 * Construct an UNSIGNED federation manifest. Call signManifest() next.
 */
export function buildManifest(p: BuildManifestParams): FederationManifest {
  const version = p.version ?? 1;
  if (!Number.isInteger(version) || version < 1) {
    throw new Error("manifest version must be an integer >= 1");
  }
  const predecessor_hash =
    p.predecessor_hash ?? (version === 1 ? GENESIS_PREDECESSOR : "");
  if (version === 1 && predecessor_hash !== GENESIS_PREDECESSOR) {
    throw new Error("genesis manifest (version 1) must use the genesis predecessor_hash");
  }
  if (!p.federation_id) throw new Error("federation_id is required");

  return {
    federation_id: p.federation_id,
    version,
    predecessor_hash,
    members: p.members.map((m) => ({ ...m })),
    accepted_circuits: p.accepted_circuits.map((c) => ({ ...c })),
  };
}

// ── sign ──────────────────────────────────────────────────────────────────

/**
 * Sign a manifest with a federation-authority Ed25519 private key.
 * Signature covers the RFC-8785-canonicalised manifest WITH the `signature`
 * field removed. Returns a new object; the input is not mutated.
 *
 * @param privKey  32-byte Ed25519 secret key (Uint8Array or hex string).
 * @param keyId    identifier recorded in signature.key_id.
 */
export function signManifest(
  manifest: FederationManifest,
  privKey: Uint8Array | string,
  keyId?: string,
): SignedManifest {
  const sk = typeof privKey === "string" ? hexToBytes(privKey) : privKey;
  const pub = ed.getPublicKey(sk);
  const msg = utf8ToBytes(canonicalize(unsignedView(manifest)));
  const sig = ed.sign(msg, sk);
  return {
    ...unsignedView(manifest),
    signature: {
      alg: "ed25519",
      key_id: keyId ?? bytesToHex(pub),
      sig: bytesToHex(sig),
    },
  };
}

// ── verify ──────────────────────────────────────────────────────────────────

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

/**
 * Verify a manifest: structural sanity + Ed25519 signature against the
 * federation authority's public key. Never throws — returns {ok,reason}.
 *
 * @param federationPubKey  the authority's Ed25519 public key (hex or bytes).
 */
export function verifyManifest(
  manifest: FederationManifest,
  federationPubKey: Uint8Array | string,
): VerifyResult {
  try {
    // structural checks
    if (!manifest || typeof manifest !== "object") {
      return { ok: false, reason: "manifest is not an object" };
    }
    if (typeof manifest.federation_id !== "string" || !manifest.federation_id) {
      return { ok: false, reason: "missing or invalid federation_id" };
    }
    if (!Number.isInteger(manifest.version) || manifest.version < 1) {
      return { ok: false, reason: "version must be an integer >= 1" };
    }
    if (
      typeof manifest.predecessor_hash !== "string" ||
      !/^sha256:[0-9a-f]{64}$/.test(manifest.predecessor_hash)
    ) {
      return { ok: false, reason: "malformed predecessor_hash" };
    }
    if (manifest.version === 1 && manifest.predecessor_hash !== GENESIS_PREDECESSOR) {
      return { ok: false, reason: "genesis manifest must use the genesis predecessor_hash" };
    }
    if (!Array.isArray(manifest.members)) {
      return { ok: false, reason: "members must be an array" };
    }
    for (const m of manifest.members) {
      if (
        !m ||
        typeof m.issuer_id !== "string" ||
        typeof m.issuer_pubkey !== "string" ||
        !/^[0-9a-f]{64}$/.test(m.issuer_pubkey)
      ) {
        return { ok: false, reason: "malformed member entry" };
      }
    }
    if (!Array.isArray(manifest.accepted_circuits)) {
      return { ok: false, reason: "accepted_circuits must be an array" };
    }
    for (const c of manifest.accepted_circuits) {
      if (
        !c ||
        typeof c.circuit_id !== "string" ||
        typeof c.vk_hash !== "string" ||
        !/^sha256:[0-9a-f]{64}$/.test(c.vk_hash)
      ) {
        return { ok: false, reason: "malformed accepted_circuit entry" };
      }
    }
    const sig = manifest.signature;
    if (!sig || sig.alg !== "ed25519") {
      return { ok: false, reason: "missing or unsupported signature" };
    }
    if (typeof sig.sig !== "string" || !/^[0-9a-f]{128}$/.test(sig.sig)) {
      return { ok: false, reason: "malformed signature bytes" };
    }

    // cryptographic check
    const pub = typeof federationPubKey === "string"
      ? hexToBytes(federationPubKey)
      : federationPubKey;
    const msg = utf8ToBytes(canonicalize(unsignedView(manifest)));
    const valid = ed.verify(hexToBytes(sig.sig), msg, pub);
    if (!valid) return { ok: false, reason: "signature verification failed" };

    return { ok: true };
  } catch (e) {
    return { ok: false, reason: "exception: " + (e instanceof Error ? e.message : String(e)) };
  }
}

// ── update ──────────────────────────────────────────────────────────────────

export interface ManifestChanges {
  addMembers?: Member[];
  /** issuer_id values to remove. */
  removeMembers?: string[];
  addCircuits?: AcceptedCircuit[];
  /** circuit_id values to remove. */
  removeCircuits?: string[];
}

/**
 * Produce the next manifest version (prev.version + 1) with the correct
 * predecessor_hash chained from `prev`, apply the requested membership /
 * circuit changes, and re-sign with `privKey`.
 *
 * `prev` MUST already be a signed manifest — its hash is the chain link.
 */
export function updateManifest(
  prev: FederationManifest,
  changes: ManifestChanges,
  privKey: Uint8Array | string,
  keyId?: string,
): SignedManifest {
  if (!prev.signature) {
    throw new Error("predecessor manifest must be signed before it can be updated");
  }

  const removeM = new Set(changes.removeMembers ?? []);
  let members = prev.members.filter((m) => !removeM.has(m.issuer_id));
  for (const add of changes.addMembers ?? []) {
    if (members.some((m) => m.issuer_id === add.issuer_id)) {
      throw new Error(`member already present: ${add.issuer_id}`);
    }
    members = [...members, { ...add }];
  }

  const removeC = new Set(changes.removeCircuits ?? []);
  let circuits = prev.accepted_circuits.filter((c) => !removeC.has(c.circuit_id));
  for (const add of changes.addCircuits ?? []) {
    if (circuits.some((c) => c.circuit_id === add.circuit_id)) {
      throw new Error(`circuit already present: ${add.circuit_id}`);
    }
    circuits = [...circuits, { ...add }];
  }

  const next = buildManifest({
    federation_id: prev.federation_id,
    members,
    accepted_circuits: circuits,
    version: prev.version + 1,
    predecessor_hash: manifestHash(prev),
  });

  return signManifest(next, privKey, keyId);
}
