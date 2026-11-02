import { existsSync, readFileSync, readdirSync } from 'node:fs';
import type { ThreatEvent } from '../types/events.js';
import { takeSnapshot, type SnapshotIO } from '../core/privileges/index.js';
import { isAutomationKeyComment } from './firewall/protected.js';

/**
 * Which authorized key a login used, by its SHA256 fingerprint: the account it
 * is authorized for and its authorized_keys comment. sshd logs only the
 * fingerprint, so without this the dashboard cannot tell a CI deploy key
 * ("github-actions-deploy@org/repo") from a person's key, and every GitHub
 * Actions deploy pages as a login from Microsoft.
 */
export interface KeyEntry {
  account: string;
  comment: string;
}

const fsIO: SnapshotIO = {
  readFile: (p) => { try { return readFileSync(p, 'utf-8'); } catch { return null; } },
  readDir: (p) => { try { return readdirSync(p); } catch { return null; } },
  exists: (p) => existsSync(p),
};

export class KeyDirectory {
  private cache: { at: number; byFp: Map<string, KeyEntry> } = { at: -Infinity, byFp: new Map() };

  constructor(
    private readonly io: SnapshotIO = fsIO,
    private readonly now: () => number = Date.now,
    private readonly ttlMs = 300_000,
  ) {}

  lookup(fingerprint: string): KeyEntry | null {
    if (this.now() - this.cache.at > this.ttlMs) {
      const byFp = new Map<string, KeyEntry>();
      for (const [account, keys] of Object.entries(takeSnapshot(this.io).keys)) {
        for (const [fp, k] of Object.entries(keys)) if (!byFp.has(fp)) byFp.set(fp, { account, comment: k.comment });
      }
      this.cache = { at: this.now(), byFp };
    }
    return this.cache.byFp.get(fingerprint) ?? null;
  }
}

/**
 * Add the key's comment and kind to an accepted SSH login, in place, so the
 * rule engine's evidence carries them to the dashboard. `key_kind` is
 * "automation" only when the authorized_keys comment says so; a key we cannot
 * find (another account's file we could not read) is "unknown", never assumed
 * to be a deploy key.
 */
export function enrichLoginEvent(event: ThreatEvent, keys: Pick<KeyDirectory, 'lookup'>): void {
  if (event.module !== 'ssh-guard') return;
  const details = event.details as Record<string, unknown> | undefined;
  const fp = details?.fingerprint;
  if (!details || typeof fp !== 'string' || !fp.startsWith('SHA256:') || 'key_kind' in details) return;
  let entry: KeyEntry | null = null;
  try { entry = keys.lookup(fp); } catch { entry = null; }
  if (!entry) {
    details.key_kind = 'unknown';
    return;
  }
  details.key_account = entry.account;
  if (entry.comment) details.key_comment = entry.comment;
  details.key_kind = isAutomationKeyComment(entry.comment) ? 'automation' : 'person';
}
