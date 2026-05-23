// ===========================================================================
// R+4 Federation — node persistence (persistence.ts)
// ===========================================================================
//
// v1.0 HARDENING — survive a restart.
//
// The original prototype kept all node state in memory: a node that restarted
// always rebooted at its *initial* manifest, silently throwing away every
// manifest version it had adopted while running. In a real deployment that is
// a correctness bug — a restarted node would serve a stale manifest to peers
// and could re-adopt a manifest it had already superseded.
//
// This module gives a node a small disk-backed store for its adopted manifest.
// It is OPT-IN: a node with no `statePath` configured uses `memoryStore` and
// behaves exactly like the original prototype (no files touched).
//
// STILL OUT OF SCOPE: persisting the peer-auth replay ledger (a restart still
// resets replay protection — bounded by the peer-auth timestamp window), and
// Byzantine-fault-tolerant consensus. See federation/MULTINODE.md.
// ===========================================================================

import * as fs from "node:fs";
import * as path from "node:path";
import { verifyManifest, type SignedManifest } from "./manifest.js";

export interface NodeStore {
  /** Load the persisted manifest, or null when there is none / it is invalid. */
  loadManifest(): SignedManifest | null;
  /** Persist the current manifest. Implementations must write atomically. */
  saveManifest(m: SignedManifest): void;
}

/**
 * No-op store — used when `statePath` is not configured. A node using this
 * store keeps no disk state and behaves exactly like the original prototype.
 */
export const memoryStore: NodeStore = {
  loadManifest: () => null,
  saveManifest: () => {},
};

/**
 * Disk-backed store rooted at `dir`. Writes are atomic: the manifest is
 * written to a temp file and then renamed over the real path, so a crash
 * mid-write can never leave a half-written manifest on disk.
 */
export function fileStore(dir: string): NodeStore {
  const manifestPath = path.join(dir, "manifest.json");
  return {
    loadManifest(): SignedManifest | null {
      try {
        if (!fs.existsSync(manifestPath)) return null;
        return JSON.parse(fs.readFileSync(manifestPath, "utf8")) as SignedManifest;
      } catch {
        // A corrupt or unreadable state file must not crash the node — it
        // falls back to the configured initial manifest.
        return null;
      }
    },
    saveManifest(m: SignedManifest): void {
      fs.mkdirSync(dir, { recursive: true });
      const tmp = `${manifestPath}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(m));
      fs.renameSync(tmp, manifestPath);
    },
  };
}

/**
 * Decide which manifest a node should boot from: the persisted one when it is
 * present, authority-signed, and strictly newer than the configured initial
 * manifest; otherwise the configured initial manifest.
 *
 * A persisted manifest that fails signature verification is ignored — a node
 * never trusts disk state over the cryptographic check.
 */
export function chooseBootManifest(
  store: NodeStore,
  initial: SignedManifest,
  authorityPk: string,
): { manifest: SignedManifest; restored: boolean } {
  const persisted = store.loadManifest();
  if (
    persisted &&
    typeof persisted.version === "number" &&
    persisted.version > initial.version &&
    verifyManifest(persisted, authorityPk).ok
  ) {
    return { manifest: persisted, restored: true };
  }
  return { manifest: initial, restored: false };
}
