import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig, loadDaemonConfig } from '../config.js';

const GOOD = '[remediation]\nbackend = "nftables"\nprotected = ["23.95.228.174"]\n';
// What a bad edit left on dev2 on 2026-10-28: a section written twice.
const BROKEN = `${GOOD}\n[alerts.smshub]\nenabled = true\nmin_severity = "critical"\nmin_severity = "critical"\n`;

describe('a config file that does not parse', () => {
  it('the daemon uses the last good copy and says why, never silent defaults', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tc-conf-'));
    const conf = join(dir, 'threatcrushd.conf');
    const lastGood = join(dir, 'state', 'last-good');
    writeFileSync(conf, GOOD);
    expect(loadDaemonConfig(conf, lastGood).error).toBeUndefined();
    writeFileSync(conf, BROKEN);
    const out = loadDaemonConfig(conf, lastGood);
    expect(out.error).toMatch(/not valid TOML/);
    expect(out.usedLastGood).toBe(true);
    expect(out.config.remediation?.protected).toEqual(['23.95.228.174']);
    expect(out.config.remediation?.backend).toBe('nftables');
  });

  it('with no good copy it reports the error and falls back to defaults', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tc-conf-'));
    const conf = join(dir, 'threatcrushd.conf');
    writeFileSync(conf, BROKEN);
    const out = loadDaemonConfig(conf, join(dir, 'nope'));
    expect(out.error).toBeTruthy();
    expect(out.usedLastGood).toBe(false);
    let seen: Error | null = null;
    loadConfig(conf, (e) => { seen = e; });
    expect(seen).not.toBeNull();
  });
});
