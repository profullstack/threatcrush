import { describe, it, expect, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ThreatEvent } from '../../types/events.js';

vi.mock('../../core/state.js', () => ({ insertEvent: () => {} }));

const { PrivilegeWatch, classifyKeyAddition, keyIsExpected, privilegeSettings } = await import('../workers/privilege-watch.js');
const { parseAuthorizedKeys } = await import('../../core/privileges/index.js');

// The key the 2026-10-27 intruder appended to root's and anthony's
// authorized_keys and authorized_keys2 on dev2 (public half, from the incident
// evidence). Split so secret scanners do not read it as a credential.
const PLANTED = ['ssh-ed25519', 'AAAAC3NzaC1lZDI1NTE5AAAAIH2uqoN4hZsSRPdE3yHg5SOGuUAifwTUKN+mxT980/n9', 'ops-recovery-20261027'].join(' ');
const OURS = ['ssh-ed25519', 'AAAAC3NzaC1lZDI1NTE5AAAAIOMmZ1qkGWyTCZ9cTZaDnF2u7f7kTqI6WcN1u0X3gSmd', 'anthony@profullstack-2026-10-28'].join(' ');
const SELFTEST = ['ssh-ed25519', 'AAAAC3NzaC1lZDI1NTE5AAAAIBk4hWb6ZbN0v8n5mK6x1xVZbAqGQ1v2d7m3rS0p9qXy', 'threatcrush-selftest'].join(' ');

function box(files: Record<string, string>) {
  const fs = { ...files };
  const io = {
    readFile: (p: string) => fs[p] ?? null,
    readDir: () => null,
    exists: (p: string) => p in fs,
  };
  const dir = mkdtempSync(join(tmpdir(), 'tc-keys-'));
  const events: ThreatEvent[] = [];
  const watch = new PrivilegeWatch({
    settings: { ...privilegeSettings({ expected_keys: ['github-actions-deploy@*'] }), geo: false, watchFiles: false },
    bus: { publish: (e: ThreatEvent) => events.push(e), on: () => {}, off: () => {} } as never,
    snapshotPath: join(dir, 'privileges.json'),
    loginsPath: join(dir, 'logins.json'),
    cursorPath: join(dir, 'cursor.json'),
    log: () => {},
    io,
    run: () => null,
  });
  return { fs, watch, events };
}

const PASSWD = 'root:x:0:0:root:/root:/bin/bash\nanthony:x:1001:1003::/home/anthony:/bin/zsh\n';

describe('authorized_keys additions', () => {
  it('pages (critical) for the planted ops-recovery key, with its comment and fingerprint', () => {
    const b = box({ '/etc/passwd': PASSWD, '/root/.ssh/authorized_keys': `${OURS}\n` });
    b.watch.checkSnapshot();
    b.fs['/root/.ssh/authorized_keys2'] = `${PLANTED}\n`;
    b.watch.checkSnapshot();
    const fp = parseAuthorizedKeys(PLANTED)[0].fingerprint;
    const ev = b.events.find((e) => e.details?.rule_id === 'priv-authorized-key-added');
    expect(ev?.severity).toBe('critical');
    expect(ev?.message).toContain('ops-recovery-20261027');
    expect(ev?.message).toContain(fp);
    expect(ev?.message).toContain('root');
    expect(ev?.details?.evidence).toBeTruthy();
    expect(ev?.source_ip).toBeUndefined();
  });

  it('an expected key (comment glob) is high, not a page', () => {
    const change = classifyKeyAddition(
      { severity: 'high', message: 'x', details: { rule_id: 'priv-authorized-key-added', account: 'anthony', fingerprint: 'SHA256:x', comment: 'github-actions-deploy@nichedb' } },
      ['github-actions-deploy@*'],
    );
    expect(change.severity).toBe('high');
    expect(keyIsExpected('SHA256:abc', 'whatever', ['SHA256:abc'])).toBe(true);
    expect(keyIsExpected('SHA256:abc', 'ops-recovery-20261027', ['github-actions-deploy@*'])).toBe(false);
  });

  it('labels the self-test key as a TEST', () => {
    const b = box({ '/etc/passwd': PASSWD, '/home/anthony/.ssh/authorized_keys': `${OURS}\n` });
    b.watch.checkSnapshot();
    b.fs['/home/anthony/.ssh/authorized_keys'] = `${OURS}\n${SELFTEST}\n`;
    b.watch.checkSnapshot();
    const ev = b.events.find((e) => e.details?.selftest === true);
    expect(ev?.severity).toBe('critical');
    expect(ev?.message).toMatch(/^\[TEST\]/);
    expect(ev?.details?.rule_id).toBe('priv-authorized-key-selftest');
  });

  it('a removed key is low', () => {
    const b = box({ '/etc/passwd': PASSWD, '/home/anthony/.ssh/authorized_keys': `${OURS}\n${PLANTED}\n` });
    b.watch.checkSnapshot();
    b.fs['/home/anthony/.ssh/authorized_keys'] = `${OURS}\n`;
    b.watch.checkSnapshot();
    expect(b.events.map((e) => e.severity)).toEqual(['low']);
  });
});
