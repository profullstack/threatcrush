import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ThreatEvent } from '../../types/events.js';
import {
  AutoUpdate,
  PKG_NAME,
  installPlan,
  isNewer,
  ownerOf,
  pickUpdate,
  updateSettings,
  type RegistryDoc,
} from '../workers/auto-update.js';

const HOUR = 3600_000;
const NOW = Date.parse('2026-10-17T12:00:00Z');
const PKG_ROOT = '/home/ops/.local/share/mise/installs/node/24.21.0/lib/node_modules/@profullstack/threatcrush';
const EXEC = '/home/ops/.local/share/mise/installs/node/24.21.0/bin/node';

function doc(latest: string, publishedAgoMs: number): RegistryDoc {
  return { 'dist-tags': { latest }, time: { [latest]: new Date(NOW - publishedAgoMs).toISOString() } };
}

describe('isNewer', () => {
  it('orders versions numerically, releases after their pre-releases', () => {
    expect(isNewer('0.13.32', '0.13.31')).toBe(true);
    expect(isNewer('0.13.10', '0.13.9')).toBe(true);
    expect(isNewer('0.14.0', '0.13.99')).toBe(true);
    expect(isNewer('0.13.31', '0.13.31')).toBe(false);
    expect(isNewer('0.13.30', '0.13.31')).toBe(false);
    expect(isNewer('1.0.0', '1.0.0-rc.1')).toBe(true);
    expect(isNewer('1.0.0-rc.1', '1.0.0')).toBe(false);
  });
});

describe('pickUpdate', () => {
  const opts = { allowMajor: false, minAgeMs: 2 * HOUR, now: NOW };

  it('takes a newer latest once it is old enough', () => {
    expect(pickUpdate(doc('0.13.32', 3 * HOUR), '0.13.31', opts)).toEqual({ version: '0.13.32' });
  });

  it('waits for a release younger than min_age, so a bad one can be pulled first', () => {
    const pick = pickUpdate(doc('0.13.32', 10 * 60_000), '0.13.31', opts);
    expect(pick.version).toBeNull();
  });

  it('stays put when current, and never downgrades', () => {
    expect(pickUpdate(doc('0.13.31', 9 * HOUR), '0.13.31', opts).version).toBeNull();
    expect(pickUpdate(doc('0.13.30', 9 * HOUR), '0.13.31', opts).version).toBeNull();
  });

  it('on a busy release day takes the newest release old enough, not nothing', () => {
    // 2026-10-17: latest kept being younger than min_age while older releases were eligible.
    const busy: RegistryDoc = {
      'dist-tags': { latest: '0.13.37' },
      time: {
        created: '2026-01-01T00:00:00Z',
        modified: new Date(NOW).toISOString(),
        '0.13.32': new Date(NOW - 9 * HOUR).toISOString(),
        '0.13.35': new Date(NOW - 3 * HOUR).toISOString(),
        '0.13.36': new Date(NOW - 2.5 * HOUR).toISOString(),
        '0.13.37': new Date(NOW - 20 * 60_000).toISOString(),
        '0.13.38-rc.1': new Date(NOW - 9 * HOUR).toISOString(),
        '0.14.0': new Date(NOW - 9 * HOUR).toISOString(), // published but never promoted to latest
      },
    };
    expect(pickUpdate(busy, '0.13.32', opts)).toEqual({ version: '0.13.36' });
    expect(pickUpdate(busy, '0.13.36', opts).version).toBeNull();
    expect((pickUpdate(busy, '0.13.36', opts) as { reason: string }).reason).toMatch(/0\.13\.37 is younger than min_age/);
  });

  it('does not cross a major unless allowed', () => {
    expect(pickUpdate(doc('1.0.0', 9 * HOUR), '0.13.31', opts).version).toBeNull();
    expect(pickUpdate(doc('1.0.0', 9 * HOUR), '0.13.31', { ...opts, allowMajor: true })).toEqual({ version: '1.0.0' });
  });
});

describe('installPlan', () => {
  const base = {
    version: '0.13.32',
    pkgRoot: PKG_ROOT,
    execPath: EXEC,
    owner: { uid: 1000, gid: 1000, home: '/home/ops' },
    npmExists: () => true,
  };

  it('under systemd as root, hands npm to a transient unit run as the install owner', () => {
    const plan = installPlan({ ...base, uid: 0, underSystemd: true });
    expect(plan.kind).toBe('run');
    if (plan.kind !== 'run') return;
    expect(plan.argv.slice(0, 3)).toEqual(['systemd-run', '--wait', '--collect']);
    expect(plan.argv).toContain('--uid=1000');
    expect(plan.argv).toContain('--setenv=HOME=/home/ops');
    expect(plan.argv.slice(-6)).toEqual([
      '/home/ops/.local/share/mise/installs/node/24.21.0/bin/npm',
      'i',
      '-g',
      `${PKG_NAME}@0.13.32`,
      '--no-fund',
      '--no-audit',
    ]);
  });

  it('a user-mode daemon that owns its install runs npm itself', () => {
    const plan = installPlan({ ...base, uid: 1000, underSystemd: false });
    expect(plan.kind === 'run' && plan.argv[0]).toBe('/home/ops/.local/share/mise/installs/node/24.21.0/bin/npm');
  });

  it('leaves anything but an npm global install, or someone else’s install, to a person', () => {
    expect(installPlan({ ...base, uid: 1000, underSystemd: false, pkgRoot: '/src/threatcrush/apps/cli' }).kind).toBe('unsupported');
    expect(installPlan({ ...base, uid: 1001, underSystemd: false }).kind).toBe('unsupported');
    expect(installPlan({ ...base, uid: 1000, underSystemd: false, npmExists: () => false }).kind).toBe('unsupported');
    expect(installPlan({ ...base, uid: 0, underSystemd: true, owner: null }).kind).toBe('unsupported');
  });
});

describe('updateSettings', () => {
  it('is on by default and off by config or env', () => {
    expect(updateSettings(undefined, {})).toEqual({ enabled: true, intervalMs: 6 * HOUR, minAgeMs: 2 * HOUR, allowMajor: false });
    expect(updateSettings({ auto: false }, {}).enabled).toBe(false);
    expect(updateSettings(undefined, { THREATCRUSH_AUTO_UPDATE: '0' }).enabled).toBe(false);
    expect(updateSettings({ interval: '1m', min_age: '0s' }, {})).toMatchObject({ intervalMs: 15 * 60_000, minAgeMs: 0 });
  });
});

describe('AutoUpdate', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  function setup(registry: RegistryDoc, runCode = 0) {
    const dir = mkdtempSync(join(tmpdir(), 'tc-autoupdate-'));
    dirs.push(dir);
    // A real npm-global layout on disk, owned by whoever runs the test.
    const prefix = join(dir, 'prefix');
    const pkgRoot = join(prefix, 'lib', 'node_modules', '@profullstack', 'threatcrush');
    mkdirSync(pkgRoot, { recursive: true });
    const events: ThreatEvent[] = [];
    const logs: string[] = [];
    const runs: string[][] = [];
    let restarts = 0;
    const updater = new AutoUpdate({
      version: '0.13.31',
      settings: { enabled: true, intervalMs: 6 * HOUR, minAgeMs: 2 * HOUR, allowMajor: false },
      pkgRoot,
      statePath: join(dir, 'auto-update.json'),
      bus: { publish: (e) => events.push(e) },
      log: (l) => logs.push(l),
      restartDaemon: () => restarts++,
      underSystemd: false,
      fetchImpl: (async () => new Response(JSON.stringify(registry))) as unknown as typeof fetch,
      run: async (argv) => {
        runs.push(argv);
        return { code: runCode, output: runCode ? 'npm ERR! EACCES' : 'added 1 package' };
      },
      now: () => NOW,
    });
    return { updater, events, logs, runs, restarts: () => restarts, dir };
  }

  // These need the test's own uid to own the install, i.e. a POSIX box.
  const posix = process.getuid ? it : it.skip;

  posix('installs, announces it in the feed, and restarts onto the new build', async () => {
    const t = setup(doc('0.13.32', 3 * HOUR));
    // npm must exist beside the node running the test for the plan to proceed.
    const result = await t.updater.check();
    if (result.includes('no npm beside')) return; // node without a sibling npm (unusual CI image)
    expect(result).toBe('updated to 0.13.32');
    expect(t.runs).toHaveLength(1);
    expect(t.runs[0]).toContain(`${PKG_NAME}@0.13.32`);
    expect(t.restarts()).toBe(1);
    expect(t.events.map((e) => e.message)).toEqual(['updating ThreatCrush 0.13.31 → 0.13.32']);
    expect(t.events[0]).toMatchObject({ module: 'auto-update', severity: 'info' });
  });

  posix('does not restart after a failed install, and does not retry the same version within a day', async () => {
    const t = setup(doc('0.13.32', 3 * HOUR), 1);
    const first = await t.updater.check();
    if (first.includes('no npm beside')) return;
    expect(first).toContain('install of 0.13.32 failed (exit 1)');
    expect(t.restarts()).toBe(0);
    expect(t.events.at(-1)?.message).toBe('auto-update to 0.13.32 failed (exit 1)');

    const second = await t.updater.check();
    expect(second).toContain('did not take');
    expect(t.runs).toHaveLength(1);
  });

  posix('force ("Update now") skips min_age and the retry window, and can delay the restart', async () => {
    vi.useFakeTimers({ now: NOW, toFake: ['setTimeout'] });
    try {
      const young = setup(doc('0.13.32', HOUR / 4)); // 15 minutes old
      expect(await young.updater.check()).toContain('younger than min_age');
      const forced = await young.updater.check({ force: true, restartDelayMs: 3000 });
      if (forced.includes('no npm beside')) return;
      expect(forced).toBe('updated to 0.13.32');
      expect(young.restarts()).toBe(0);
      vi.advanceTimersByTime(3500);
      expect(young.restarts()).toBe(1);

      const failing = setup(doc('0.13.32', 3 * HOUR), 1);
      await failing.updater.check();
      expect(await failing.updater.check()).toContain('did not take');
      expect(await failing.updater.check({ force: true })).toContain('install of 0.13.32 failed');
      expect(failing.runs).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('does nothing when already current or the registry is down', async () => {
    const current = setup(doc('0.13.31', 9 * HOUR));
    expect(await current.updater.check()).toBe('up to date (0.13.31)');
    expect(current.runs).toHaveLength(0);

    const t = setup(doc('0.13.32', 9 * HOUR));
    const down = new AutoUpdate({
      ...(t.updater as unknown as { opts: ConstructorParameters<typeof AutoUpdate>[0] }).opts,
      fetchImpl: (async () => {
        throw new Error('ENOTFOUND registry.npmjs.org');
      }) as unknown as typeof fetch,
    });
    expect(await down.check()).toContain('registry unreachable');
    expect(t.runs).toHaveLength(0);
  });
});

describe('ownerOf', () => {
  it('finds the owner and their home from passwd', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tc-owner-'));
    const uid = process.getuid?.() ?? 0;
    const passwd = join(dir, 'passwd');
    writeFileSync(passwd, `root:x:0:0:root:/root:/bin/sh\nops:x:${uid}:${uid}::/home/ops-test:/bin/sh\n`);
    expect(ownerOf(dir, passwd)).toMatchObject({ uid, home: uid === 0 ? '/root' : '/home/ops-test' });
    rmSync(dir, { recursive: true, force: true });
  });
});
