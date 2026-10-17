import { describe, expect, it } from 'vitest';
import { mkdtempSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compareDebianVersions } from '../patches/dpkg-version.js';
import {
  checkPatches,
  fixedByUpdate,
  osvEcosystem,
  parseAptSimulation,
  parseCandidateSources,
  parseOsRelease,
  patchFinding,
} from '../patches/index.js';

describe('compareDebianVersions', () => {
  const cases: Array<[string, string, -1 | 0 | 1]> = [
    ['1.0', '1.0', 0],
    ['1.0', '1.1', -1],
    ['1.10', '1.9', 1],
    ['1:1.0', '2.0', 1], // epoch wins
    ['1.0~rc1', '1.0', -1], // tilde sorts before the end
    ['1.0~rc1', '1.0~rc2', -1],
    ['1.0a', '1.0', 1],
    ['1.0a', '1.0+', -1], // letters before non-letters
    ['3.0.13-0ubuntu3.1', '3.0.13-0ubuntu3.4', -1],
    ['3.0.13-0ubuntu3.10', '3.0.13-0ubuntu3.9', 1],
    ['2.39-0ubuntu8.3', '2.39-0ubuntu8', 1],
    ['1:10.2p1-2ubuntu3.8', '1:10.2p1-2ubuntu3.10', -1],
    ['1.0-1', '1.0', 1],
    ['007', '7', 0],
  ];
  it.each(cases)('%s vs %s', (a, b, want) => {
    expect(Math.sign(compareDebianVersions(a, b))).toBe(want);
    expect(Math.sign(compareDebianVersions(b, a))).toBe(-want || 0);
  });
});

describe('osvEcosystem', () => {
  it('names Ubuntu LTS, Ubuntu interim and Debian releases the way OSV does', () => {
    expect(osvEcosystem(parseOsRelease('ID=ubuntu\nVERSION_ID="24.04"\nVERSION="24.04.1 LTS (Noble Numbat)"'))).toBe('Ubuntu:24.04:LTS');
    expect(osvEcosystem(parseOsRelease('ID=ubuntu\nVERSION_ID="25.10"\nVERSION="25.10 (Questing Quokka)"'))).toBe('Ubuntu:25.10');
    expect(osvEcosystem(parseOsRelease('ID=debian\nVERSION_ID="12"'))).toBe('Debian:12');
  });

  it('refuses derivatives and other distributions rather than guessing', () => {
    expect(osvEcosystem(parseOsRelease('ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="22"\nUBUNTU_CODENAME=jammy'))).toBeNull();
    expect(osvEcosystem(parseOsRelease('ID="rocky"\nVERSION_ID="9.4"'))).toBeNull();
  });
});

describe('parseAptSimulation', () => {
  it('keeps upgrades, marks the -security ones and skips new installs', () => {
    const out = parseAptSimulation([
      'Reading package lists...',
      'Inst libssl3t64 [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])',
      'Inst google-chrome-stable [155.0.8059.79-1] (155.0.8059.84-1 Google:1.0/stable [amd64])',
      'Inst linux-image-6.8.0-90-generic (6.8.0-90.91 Ubuntu:24.04/noble-security [amd64])',
      'Inst tzdata [2024a-3ubuntu1.1] (2025b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all]) []',
      'Inst libc6 [2.36-9+deb12u7] (2.36-9+deb12u9 Debian-Security:12/stable-security [amd64])',
      'Conf libssl3t64 (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates [amd64])',
    ].join('\n'));
    expect(out).toEqual([
      { name: 'libssl3t64', installed: '3.0.13-0ubuntu3.1', candidate: '3.0.13-0ubuntu3.4', security: true },
      { name: 'google-chrome-stable', installed: '155.0.8059.79-1', candidate: '155.0.8059.84-1', security: false },
      { name: 'tzdata', installed: '2024a-3ubuntu1.1', candidate: '2025b-0ubuntu0.24.04', security: false },
      { name: 'libc6', installed: '2.36-9+deb12u7', candidate: '2.36-9+deb12u9', security: true },
    ]);
  });
});

describe('parseCandidateSources', () => {
  it('reads a differently-versioned Source: and falls back to the binary', () => {
    const map = parseCandidateSources([
      'Package: libssl3t64\nVersion: 3.0.13-0ubuntu3.4\nSource: openssl\n',
      'Package: linux-image-generic\nVersion: 6.8.0-90.91\nSource: linux-meta (6.8.0-90.92)\n',
      'Package: sudo\nVersion: 1.9.15p5-3ubuntu5.1\n',
    ].join('\n'));
    expect(map.get('libssl3t64=3.0.13-0ubuntu3.4')).toEqual({ source: 'openssl', version: '3.0.13-0ubuntu3.4' });
    expect(map.get('linux-image-generic=6.8.0-90.91')).toEqual({ source: 'linux-meta', version: '6.8.0-90.92' });
    expect(map.get('sudo=1.9.15p5-3ubuntu5.1')).toEqual({ source: 'sudo', version: '1.9.15p5-3ubuntu5.1' });
  });
});

const ECO = 'Ubuntu:24.04:LTS';
const rec = (id: string, fixedByEco: Record<string, string | undefined>, score = 'high') => ({
  id: `UBUNTU-${id}`,
  upstream: [id],
  severity: [{ type: 'Ubuntu', score }],
  affected: Object.entries(fixedByEco).map(([ecosystem, fixed]) => ({
    package: { name: 'openssl', ecosystem },
    ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, ...(fixed ? [{ fixed }] : [])] }],
  })),
});

describe('fixedByUpdate', () => {
  it('counts a fix between installed and candidate, for this release only', () => {
    const inst = '3.0.13-0ubuntu3.1';
    const cand = '3.0.13-0ubuntu3.4';
    expect(fixedByUpdate(rec('CVE-1', { [ECO]: '3.0.13-0ubuntu3.4' }), ECO, 'openssl', inst, cand)).toBe(true);
    // Fixed only in a newer update than apt offers: not fixed by this one.
    expect(fixedByUpdate(rec('CVE-2', { [ECO]: '3.0.13-0ubuntu3.5' }), ECO, 'openssl', inst, cand)).toBe(false);
    // Already fixed in what is installed.
    expect(fixedByUpdate(rec('CVE-3', { [ECO]: '3.0.13-0ubuntu3.1' }), ECO, 'openssl', inst, cand)).toBe(false);
    // No fix released.
    expect(fixedByUpdate(rec('CVE-4', { [ECO]: undefined }), ECO, 'openssl', inst, cand)).toBe(false);
    // Fixed in another release only.
    expect(fixedByUpdate(rec('CVE-5', { 'Ubuntu:22.04:LTS': '3.0.2-0ubuntu1.18' }), ECO, 'openssl', inst, cand)).toBe(false);
  });
});

function fakeExec(outputs: Record<string, string>) {
  return async (file: string) => {
    if (!(file in outputs)) throw new Error(`unexpected exec ${file}`);
    return outputs[file];
  };
}

function freshLists(): string {
  const dir = mkdtempSync(join(tmpdir(), 'tc-apt-lists-'));
  writeFileSync(join(dir, 'archive.ubuntu.com_ubuntu_dists_noble-security_InRelease'), '');
  return dir;
}

const UBUNTU = 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION="24.04.1 LTS (Noble Numbat)"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"';

describe('checkPatches', () => {
  it('reports only security updates, grouped by source, with the CVEs they fix', async () => {
    const queried: string[] = [];
    const report = await checkPatches({
      osRelease: UBUNTU,
      aptListsDir: freshLists(),
      exec: fakeExec({
        'apt-get': [
          'Inst libssl3t64 [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-security [amd64])',
          'Inst openssl [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-security [amd64])',
          'Inst tzdata [2024a-3ubuntu1.1] (2025b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all])',
        ].join('\n'),
        'dpkg-query': 'libssl3t64|openssl|3.0.13-0ubuntu3.1\nopenssl|openssl|3.0.13-0ubuntu3.1\n',
        'apt-cache': 'Package: libssl3t64\nVersion: 3.0.13-0ubuntu3.4\nSource: openssl\n\nPackage: openssl\nVersion: 3.0.13-0ubuntu3.4\n',
      }),
      fetchImpl: async (_url, init) => {
        queried.push(JSON.parse(String(init?.body)).package.name);
        return new Response(JSON.stringify({
          vulns: [
            rec('CVE-2024-0001', { [ECO]: '3.0.13-0ubuntu3.4' }, 'critical'),
            rec('CVE-2024-0002', { [ECO]: '3.0.13-0ubuntu3.2' }, 'medium'),
            rec('CVE-2024-0003', { [ECO]: undefined }, 'high'),
          ],
        }));
      },
    });

    expect(queried).toEqual(['openssl']); // one query per source package, not per binary
    expect(report.supported).toBe(true);
    expect(report.lists_stale).toBe(false);
    expect(report.upgradable).toBe(3);
    expect(report.packages).toEqual([{
      source: 'openssl',
      binaries: ['libssl3t64', 'openssl'],
      installed: '3.0.13-0ubuntu3.1',
      candidate: '3.0.13-0ubuntu3.4',
      severity: 'critical',
      cves: [{ id: 'CVE-2024-0001', severity: 'critical' }, { id: 'CVE-2024-0002', severity: 'medium' }],
    }]);
    expect(report.counts).toMatchObject({ packages: 1, cves: 2, critical: 1, medium: 1, high: 0 });

    const finding = patchFinding(report);
    expect(finding).toMatchObject({ key: 'os-patches', status: 'fail', severity: 'critical' });
    expect(finding.title).toBe('1 package with security fixes available: 2 CVEs (1 critical)');
    expect(finding.details).toMatchObject({ kind: 'os-patches', counts: { cves: 2 } });
  });

  it('still lists a security update when OSV is unreachable', async () => {
    const report = await checkPatches({
      osRelease: UBUNTU,
      aptListsDir: freshLists(),
      exec: fakeExec({
        'apt-get': 'Inst sudo [1.9.15p5-3ubuntu5] (1.9.15p5-3ubuntu5.1 Ubuntu:24.04/noble-security [amd64])',
        'dpkg-query': 'sudo|sudo|1.9.15p5-3ubuntu5\n',
        'apt-cache': '',
      }),
      fetchImpl: async () => new Response('', { status: 503 }),
    });
    expect(report.packages).toHaveLength(1);
    expect(report.packages[0]).toMatchObject({ source: 'sudo', severity: 'medium', cves: [] });
    expect(report.osv_error).toMatch(/HTTP 503/);
    expect(patchFinding(report)).toMatchObject({ status: 'warn', severity: 'medium' });
  });

  it('passes a clean box and warns when the package lists are stale', async () => {
    const opts = { osRelease: UBUNTU, exec: fakeExec({ 'apt-get': 'Reading package lists...\n' }) };
    const clean = await checkPatches({ ...opts, aptListsDir: freshLists() });
    expect(patchFinding(clean)).toMatchObject({ status: 'pass', title: 'No pending security updates' });

    const old = freshLists();
    const weekAgo = new Date(Date.now() - 7 * 86_400_000);
    utimesSync(join(old, 'archive.ubuntu.com_ubuntu_dists_noble-security_InRelease'), weekAgo, weekAgo);
    const stale = await checkPatches({ ...opts, aptListsDir: old });
    expect(stale.lists_stale).toBe(true);
    expect(patchFinding(stale)).toMatchObject({ status: 'warn', title: 'No pending security updates (package lists stale)' });
  });

  it('says why on a distribution it does not support', async () => {
    const report = await checkPatches({ osRelease: 'ID="rocky"\nVERSION_ID="9.4"\nPRETTY_NAME="Rocky Linux 9.4"', exec: fakeExec({}) });
    expect(report.supported).toBe(false);
    expect(report.reason).toMatch(/Rocky Linux 9.4/);
    expect(patchFinding(report)).toMatchObject({ status: 'warn', severity: 'info' });
  });
});
