import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type * as LoaderModule from '../rules/loader.js';

/**
 * Rules used to declare `remediation.ttl_seconds` and `rules show` printed it,
 * but since the escalation ladder (PRD 0010) nothing reads it: every ban is
 * 1m → 2m → 3m … whatever the rule says. An operator's rule file that still
 * carries it must keep loading, be told once that the value does nothing, and
 * never be shown a ban length it will not get.
 */
const dir = mkdtempSync(join(tmpdir(), 'tc-rules-'));

// `rules show` reads /etc/threatcrush/rules.d; point it at the fixture instead.
vi.mock('../rules/loader.js', async (importOriginal) => {
  const real = await importOriginal<typeof LoaderModule>();
  return { loadAllRules: () => real.loadAllRules(dir) };
});

// Imported after the mock is registered, so both see the fixture directory.
const { loadAllRules } = await import('../rules/loader.js');
const { rulesShowCommand } = await import('../../commands/rules.js');

const custom = {
  id: 'custom-wp-login',
  title: 'WordPress login hammering',
  description: 'Repeated wp-login.php posts',
  version: '1.0.0',
  category: 'web',
  severity: 'high',
  source_types: ['nginx'],
  match: { field: 'message', operator: 'contains', value: 'wp-login.php' },
  threshold: 10,
  window_seconds: 60,
  cooldown_seconds: 300,
  tags: ['web'],
  remediation: { action: 'block', ttl_seconds: 86400, description: 'Block the hammering address' },
  enabled: true,
};

writeFileSync(
  join(dir, 'local.json'),
  JSON.stringify([
    custom,
    // Overriding a shipped rule, the other way an old ttl_seconds reaches us.
    { id: 'ssh-brute-force', title: 'SSH brute force', match: { field: 'message', operator: 'contains', value: 'Failed password' }, remediation: { action: 'block', ttl_seconds: 604800 } },
    { ...custom, id: 'custom-no-ttl', remediation: { action: 'block' } },
  ]),
);

afterEach(() => vi.restoreAllMocks());
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('a rule file that still sets ttl_seconds', () => {
  it('loads every rule and warns once for each rule that sets it', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const rules = loadAllRules();

    const byId = (id: string) => rules.find((r) => r.id === id);
    expect(byId('custom-wp-login')?.remediation?.action).toBe('block');
    expect(byId('ssh-brute-force')?.remediation?.action).toBe('block');
    expect(byId('custom-no-ttl')).toBeDefined();

    const ttlWarnings = warn.mock.calls.map((c) => String(c[0])).filter((m) => m.includes('ttl_seconds'));
    expect(ttlWarnings).toHaveLength(2);
    expect(ttlWarnings.some((m) => m.includes('custom-wp-login'))).toBe(true);
    expect(ttlWarnings.some((m) => m.includes('ssh-brute-force'))).toBe(true);
  });

  it('does not carry the ignored value into what the engine emits', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    for (const rule of loadAllRules()) {
      expect(rule.remediation ?? {}, rule.id).not.toHaveProperty('ttl_seconds');
    }
  });

  it('is not shown a ban length by `rules show`', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    await rulesShowCommand('custom-wp-login');
    const out = log.mock.calls.map((c) => c.join(' ')).join('\n');

    expect(out).toContain('custom-wp-login');
    expect(out).not.toMatch(/ttl/i);
    expect(out).not.toContain('86400');
    expect(out).toMatch(/ladder/);
  });
});
