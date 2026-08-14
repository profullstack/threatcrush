import { createHash, verify as verifySignature } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  writeFileSync,
} from 'node:fs';
import { join, relative, sep } from 'node:path';
import { PATHS } from './paths.js';

/**
 * TC-32: threatcrushd runs as root and used to `await import()` anything sitting
 * in its module directory. Modules arrive from the public marketplace or an
 * arbitrary Git URL, so publishing a module was equivalent to remote code
 * execution as root on every host that installed it.
 *
 * Loading is now gated on an explicit local decision. A module runs only if the
 * operator trusted it AND its contents still hash to what they trusted. That
 * turns a silent supply-chain compromise into something a human has to approve,
 * and makes post-install tampering fail closed.
 *
 * Ed25519 signatures are verified when a module ships one and publisher keys
 * are pinned; the marketplace does not emit signatures yet, so this is an
 * additional check rather than the primary gate.
 */

const TRUST_FILE = join(PATHS.configDir, 'trusted-modules.json');
const PUBLISHER_KEYS_FILE = join(PATHS.configDir, 'publisher-keys.json');

/** Never contributes to identity: VCS metadata is not executed. */
const DIGEST_EXCLUDED_DIRS = new Set(['.git']);

export interface TrustRecord {
  digest: string;
  trustedAt: string;
  source: string;
}

interface TrustFile {
  version: 1;
  modules: Record<string, TrustRecord>;
}

export interface TrustVerdict {
  ok: boolean;
  reason?: string;
}

interface DigestEntry {
  path: string;
  isSymlink: boolean;
}

function collectFiles(root: string, dir = root, out: DigestEntry[] = []): DigestEntry[] {
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  )) {
    const full = join(dir, entry.name);
    if (entry.isSymbolicLink()) {
      // Recorded by link target, never followed — see computeModuleDigest.
      out.push({ path: full, isSymlink: true });
    } else if (entry.isDirectory()) {
      if (DIGEST_EXCLUDED_DIRS.has(entry.name)) continue;
      collectFiles(root, full, out);
    } else if (entry.isFile()) {
      out.push({ path: full, isSymlink: false });
    }
  }
  return out;
}

/**
 * SHA-256 over every file in the module, path included. node_modules is hashed
 * too — a dependency is exactly where hostile code would hide, and skipping it
 * would let an attacker swap a transitive package without breaking the digest.
 * Symlinks are hashed by their target string, not by following them, so a link
 * repointed at /etc/shadow changes the digest instead of reading the file.
 */
export function computeModuleDigest(modulePath: string): string {
  const hash = createHash('sha256');

  for (const entry of collectFiles(modulePath)) {
    // Normalize to POSIX separators so a digest taken on one platform matches.
    const relPath = relative(modulePath, entry.path).split(sep).join('/');
    hash.update(relPath);
    hash.update('\0');

    if (entry.isSymlink) {
      hash.update('symlink:');
      hash.update(readlinkSync(entry.path));
    } else {
      hash.update('file:');
      hash.update(readFileSync(entry.path));
    }
    hash.update('\0');
  }

  return hash.digest('hex');
}

function readTrustFile(): TrustFile {
  if (!existsSync(TRUST_FILE)) return { version: 1, modules: {} };
  try {
    const parsed = JSON.parse(readFileSync(TRUST_FILE, 'utf-8')) as Partial<TrustFile>;
    if (parsed.version !== 1 || typeof parsed.modules !== 'object' || !parsed.modules) {
      return { version: 1, modules: {} };
    }
    return { version: 1, modules: parsed.modules };
  } catch {
    // A corrupt ledger must not be read as "everything is trusted".
    return { version: 1, modules: {} };
  }
}

function writeTrustFile(file: TrustFile): void {
  writeFileSync(TRUST_FILE, JSON.stringify(file, null, 2) + '\n', { mode: 0o600 });
  try {
    chmodSync(TRUST_FILE, 0o600);
  } catch {
    // best-effort
  }
}

export function trustModule(name: string, modulePath: string, source: string): TrustRecord {
  const file = readTrustFile();
  const record: TrustRecord = {
    digest: computeModuleDigest(modulePath),
    trustedAt: new Date().toISOString(),
    source,
  };
  file.modules[name] = record;
  writeTrustFile(file);
  return record;
}

export function untrustModule(name: string): boolean {
  const file = readTrustFile();
  if (!file.modules[name]) return false;
  delete file.modules[name];
  writeTrustFile(file);
  return true;
}

export function listTrustedModules(): Record<string, TrustRecord> {
  return readTrustFile().modules;
}

/** Pinned publisher keys, as { keyId: "<SPKI PEM>" }. Absent file = none pinned. */
function readPublisherKeys(): Record<string, string> {
  if (!existsSync(PUBLISHER_KEYS_FILE)) return {};
  try {
    const parsed = JSON.parse(readFileSync(PUBLISHER_KEYS_FILE, 'utf-8')) as Record<string, string>;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * A module may ship mod.sig: { keyId, signature } (base64) over its digest.
 * When publisher keys are pinned, an unsigned or badly-signed module is
 * rejected outright, whatever the local trust ledger says.
 */
export function verifyModuleSignature(modulePath: string, digest: string): TrustVerdict {
  const keys = readPublisherKeys();
  const pinnedKeyIds = Object.keys(keys);
  const sigPath = join(modulePath, 'mod.sig');

  if (pinnedKeyIds.length === 0) {
    return { ok: true };
  }

  if (!existsSync(sigPath)) {
    return { ok: false, reason: 'publisher keys are pinned but the module ships no mod.sig' };
  }

  let parsed: { keyId?: string; signature?: string };
  try {
    parsed = JSON.parse(readFileSync(sigPath, 'utf-8')) as { keyId?: string; signature?: string };
  } catch {
    return { ok: false, reason: 'mod.sig is not valid JSON' };
  }

  if (!parsed.keyId || !parsed.signature) {
    return { ok: false, reason: 'mod.sig is missing keyId or signature' };
  }

  const publicKey = keys[parsed.keyId];
  if (!publicKey) {
    return { ok: false, reason: `mod.sig references unpinned key "${parsed.keyId}"` };
  }

  try {
    // Ed25519 takes the message directly (algorithm is null).
    const valid = verifySignature(
      null,
      Buffer.from(digest, 'hex'),
      publicKey,
      Buffer.from(parsed.signature, 'base64'),
    );
    return valid ? { ok: true } : { ok: false, reason: 'mod.sig signature does not match' };
  } catch (err) {
    return { ok: false, reason: `signature check failed: ${String((err as Error).message || err)}` };
  }
}

/**
 * The gate the daemon calls immediately before importing a module.
 */
export function verifyModuleTrust(name: string, modulePath: string): TrustVerdict {
  let digest: string;
  try {
    digest = computeModuleDigest(modulePath);
  } catch (err) {
    return { ok: false, reason: `could not hash module: ${String((err as Error).message || err)}` };
  }

  const signature = verifyModuleSignature(modulePath, digest);
  if (!signature.ok) return signature;

  const record = readTrustFile().modules[name];
  if (!record) {
    return {
      ok: false,
      reason: `not trusted — review it, then run: threatcrush modules trust ${name}`,
    };
  }

  if (record.digest !== digest) {
    return {
      ok: false,
      reason:
        `contents changed since it was trusted on ${record.trustedAt} — ` +
        `re-review it, then run: threatcrush modules trust ${name}`,
    };
  }

  return { ok: true };
}
