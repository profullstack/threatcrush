import { spawn } from 'node:child_process';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import type { ThreatEvent } from '../../types/events.js';
import type { UpdateSection } from '../../types/config.js';
import { parseDuration } from '../firewall/backoff.js';

/**
 * The daemon keeps itself current.
 *
 * Every box ran whatever version it was installed with until someone logged in
 * and upgraded it: seed1 sat on 0.13.20 for weeks, missing the event pruning
 * that shipped in 0.13.22, until its state.db was 138 GB and the daemon could
 * no longer start. So the daemon checks the registry itself and upgrades.
 *
 * Guard rails, because a bad release would otherwise reach every box at once:
 *   - a release must be `min_age` old (default 2h) before any box takes it,
 *     which leaves time to unpublish or supersede it;
 *   - checks are jittered, so the fleet does not restart in step;
 *   - a major version is never crossed unless `allow_major = true`;
 *   - a version that was tried and did not take is not retried for a day.
 *
 * Installing: the systemd unit is sandboxed (ProtectSystem/ProtectHome), so the
 * daemon cannot write its own install. Under systemd it hands `npm i -g` to a
 * transient unit (`systemd-run`) outside the sandbox, run as whoever owns the
 * install so file ownership stays right; a user-mode daemon runs npm itself.
 * Either way it then restarts onto the new build.
 */

export const PKG_NAME = '@profullstack/threatcrush';
const REGISTRY = `https://registry.npmjs.org/${PKG_NAME}`;
const DEFAULT_INTERVAL_MS = 6 * 3600_000;
const DEFAULT_MIN_AGE_MS = 2 * 3600_000;
const RETRY_AFTER_MS = 24 * 3600_000;

/** Is semver `a` newer than `b`? Pre-releases sort before their release. */
export function isNewer(a: string, b: string): boolean {
  const parse = (v: string) => {
    const [core, pre] = v.replace(/^v/, '').split('-', 2);
    return { nums: core.split('.').map((n) => Number.parseInt(n, 10) || 0), pre: pre ?? null };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) {
    if ((x.nums[i] ?? 0) !== (y.nums[i] ?? 0)) return (x.nums[i] ?? 0) > (y.nums[i] ?? 0);
  }
  if (x.pre === y.pre) return false;
  if (x.pre === null) return true;
  if (y.pre === null) return false;
  return x.pre > y.pre;
}

export interface RegistryDoc {
  'dist-tags'?: { latest?: string };
  time?: Record<string, string>;
}

/**
 * The version to move to, or null with the reason not to: the newest stable
 * release that is newer than this one, no newer than `latest` (a box never
 * jumps past what was promoted), on the same major unless allowed, and at
 * least `min_age` old.
 *
 * Looking only at `latest` stranded the fleet on a busy release day: on
 * 2026-10-17 five releases shipped inside two hours of each other, `latest`
 * was always younger than min_age, and every box stayed on 0.13.32 while
 * 0.13.33–0.13.36 were old enough to take.
 */
export function pickUpdate(
  doc: RegistryDoc,
  current: string,
  opts: { allowMajor: boolean; minAgeMs: number; now: number },
): { version: string } | { version: null; reason: string } {
  const latest = doc['dist-tags']?.latest;
  if (!latest) return { version: null, reason: 'registry has no latest tag' };
  if (!isNewer(latest, current)) return { version: null, reason: `up to date (${current})` };
  const major = (v: string) => Number.parseInt(v.replace(/^v/, ''), 10);

  let best: string | null = null;
  for (const [v, when] of Object.entries(doc.time ?? {})) {
    if (!/^\d+\.\d+\.\d+$/.test(v)) continue; // `created`, `modified`, prereleases
    if (!isNewer(v, current) || isNewer(v, latest)) continue;
    if (!opts.allowMajor && major(v) !== major(current)) continue;
    const published = Date.parse(when);
    if (!Number.isFinite(published) || opts.now - published < opts.minAgeMs) continue;
    if (!best || isNewer(v, best)) best = v;
  }
  if (best) return { version: best };

  if (!opts.allowMajor && major(latest) !== major(current)) {
    return { version: null, reason: `${latest} is a new major; set [update] allow_major = true to take it` };
  }
  if (!Number.isFinite(Date.parse(doc.time?.[latest] ?? ''))) return { version: null, reason: `no publish time for ${latest}` };
  return { version: null, reason: `${latest} is younger than min_age, and nothing older is newer than ${current}; waiting` };
}

export type InstallPlan =
  | { kind: 'run'; argv: string[]; env?: Record<string, string> }
  | { kind: 'unsupported'; reason: string };

/**
 * How to install `version` over the copy this daemon runs from. Only the
 * layout every installer produces is handled: an npm global install,
 * `<prefix>/lib/node_modules/@profullstack/threatcrush`, beside the node that
 * runs it. Anything else (a pnpm store, a git checkout) is left to a person.
 */
export function installPlan(opts: {
  version: string;
  pkgRoot: string;
  execPath: string;
  uid: number;
  owner: { uid: number; gid: number; home: string } | null;
  underSystemd: boolean;
  npmExists: (path: string) => boolean;
}): InstallPlan {
  const expected = `${sep}lib${sep}node_modules${sep}@profullstack${sep}threatcrush`;
  if (!opts.pkgRoot.endsWith(expected)) {
    return { kind: 'unsupported', reason: `not an npm global install (${opts.pkgRoot}); run \`threatcrush update\`` };
  }
  const nodeBin = dirname(opts.execPath);
  const npm = join(nodeBin, 'npm');
  if (!opts.npmExists(npm)) return { kind: 'unsupported', reason: `no npm beside ${opts.execPath}` };
  if (!opts.owner) return { kind: 'unsupported', reason: `cannot tell who owns ${opts.pkgRoot}` };

  const npmArgs = [npm, 'i', '-g', `${PKG_NAME}@${opts.version}`, '--no-fund', '--no-audit'];
  const path = `${nodeBin}:/usr/local/bin:/usr/bin:/bin`;

  if (opts.underSystemd && opts.uid === 0) {
    return {
      kind: 'run',
      argv: [
        'systemd-run',
        '--wait',
        '--collect',
        '--quiet',
        `--unit=threatcrush-autoupdate-${opts.version.replace(/[^0-9A-Za-z]/g, '-')}`,
        `--uid=${opts.owner.uid}`,
        `--gid=${opts.owner.gid}`,
        `--setenv=HOME=${opts.owner.home}`,
        `--setenv=PATH=${path}`,
        ...npmArgs,
      ],
    };
  }
  if (opts.uid === opts.owner.uid) {
    return { kind: 'run', argv: npmArgs, env: { PATH: path } };
  }
  return {
    kind: 'unsupported',
    reason: `install is owned by uid ${opts.owner.uid}, daemon runs as ${opts.uid}; run \`threatcrush update\` as that user`,
  };
}

/** Owner of `path` with their home directory, from /etc/passwd. */
export function ownerOf(path: string, passwd = '/etc/passwd'): { uid: number; gid: number; home: string } | null {
  try {
    const st = statSync(path);
    let home = st.uid === 0 ? '/root' : '';
    try {
      for (const line of readFileSync(passwd, 'utf8').split('\n')) {
        const f = line.split(':');
        if (Number(f[2]) === st.uid && f[5]) home = f[5];
      }
    } catch { /* no passwd: keep the guess */ }
    return home ? { uid: st.uid, gid: st.gid, home } : null;
  } catch {
    return null;
  }
}

export interface UpdateSettings {
  enabled: boolean;
  intervalMs: number;
  minAgeMs: number;
  allowMajor: boolean;
}

/** `[update]` with defaults. On unless `auto = false` or THREATCRUSH_AUTO_UPDATE=0. */
export function updateSettings(section: UpdateSection | undefined, env: NodeJS.ProcessEnv = process.env): UpdateSettings {
  const interval = parseDuration(section?.interval);
  const minAge = parseDuration(section?.min_age);
  return {
    enabled: section?.auto !== false && env.THREATCRUSH_AUTO_UPDATE !== '0',
    intervalMs: interval ? Math.max(15 * 60, interval) * 1000 : DEFAULT_INTERVAL_MS,
    minAgeMs: minAge !== null ? minAge * 1000 : DEFAULT_MIN_AGE_MS,
    allowMajor: section?.allow_major === true,
  };
}

export interface AutoUpdateOptions {
  version: string;
  settings: UpdateSettings;
  /** Where the running package lives (the dir holding dist/). */
  pkgRoot: string;
  /** Records the last attempt, so a version that did not take is not retried in a loop. */
  statePath: string;
  bus: { publish(event: ThreatEvent): void };
  log: (line: string) => void;
  restartDaemon: () => void;
  underSystemd?: boolean;
  fetchImpl?: typeof fetch;
  /** Runs argv to completion; resolves to its exit code and the tail of its output. */
  run?: (argv: string[], env?: Record<string, string>) => Promise<{ code: number; output: string }>;
  now?: () => number;
  random?: () => number;
}

function defaultRun(argv: string[], env?: Record<string, string>): Promise<{ code: number; output: string }> {
  return new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), {
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    const keep = (b: Buffer) => {
      output = (output + b.toString()).slice(-4000);
    };
    child.stdout?.on('data', keep);
    child.stderr?.on('data', keep);
    child.on('error', (err) => resolve({ code: -1, output: err.message }));
    child.on('close', (code) => resolve({ code: code ?? -1, output }));
  });
}

export class AutoUpdate {
  private timer: NodeJS.Timeout | null = null;
  private busy = false;
  private readonly fetchImpl: typeof fetch;
  private readonly run: NonNullable<AutoUpdateOptions['run']>;
  private readonly now: () => number;
  private readonly random: () => number;

  constructor(private readonly opts: AutoUpdateOptions) {
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.run = opts.run ?? defaultRun;
    this.now = opts.now ?? Date.now;
    this.random = opts.random ?? Math.random;
  }

  start(): void {
    if (!this.opts.settings.enabled) {
      this.opts.log('[update] auto-update off ([update] auto = false or THREATCRUSH_AUTO_UPDATE=0)');
      return;
    }
    // First look 10-40 minutes after start, so a restart storm (or the restart
    // that follows an update) never turns into a registry hammering.
    this.schedule(10 * 60_000 + this.random() * 30 * 60_000);
  }

  stop(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private schedule(ms: number): void {
    this.timer = setTimeout(() => {
      void this.check().finally(() => {
        // Up to an hour of jitter on every interval, so boxes drift apart.
        if (this.timer !== null) this.schedule(this.opts.settings.intervalMs + this.random() * 3600_000);
      });
    }, ms);
    this.timer.unref?.();
  }

  /** One check; returns what it did, for logs and tests. */
  async check(): Promise<string> {
    if (this.busy) return 'busy';
    this.busy = true;
    try {
      let doc: RegistryDoc;
      try {
        const res = await this.fetchImpl(REGISTRY, {
          headers: { accept: 'application/json' },
          signal: AbortSignal.timeout(20_000),
        });
        if (!res.ok) return this.note(`registry answered ${res.status}`);
        doc = (await res.json()) as RegistryDoc;
      } catch (err) {
        return this.note(`registry unreachable: ${(err as Error).message}`);
      }

      const pick = pickUpdate(doc, this.opts.version, {
        allowMajor: this.opts.settings.allowMajor,
        minAgeMs: this.opts.settings.minAgeMs,
        now: this.now(),
      });
      // Silent only when there is nothing newer: a deferral is logged, so an
      // updater that keeps waiting is visible instead of looking like it never ran.
      if (pick.version === null) return this.note(pick.reason, !pick.reason.startsWith('up to date'));
      const target = pick.version;

      const last = this.lastAttempt();
      if (last?.version === target && this.now() - last.at < RETRY_AFTER_MS) {
        return this.note(`${target} was tried at ${new Date(last.at).toISOString()} and did not take; retrying after a day`);
      }

      const plan = installPlan({
        version: target,
        pkgRoot: this.opts.pkgRoot,
        execPath: process.execPath,
        uid: process.getuid?.() ?? -1,
        owner: ownerOf(this.opts.pkgRoot),
        underSystemd: this.opts.underSystemd ?? Boolean(process.env.INVOCATION_ID),
        npmExists: existsSync,
      });
      if (plan.kind === 'unsupported') return this.note(`${target} is available but cannot self-install: ${plan.reason}`);

      this.recordAttempt(target);
      this.event(`updating ThreatCrush ${this.opts.version} → ${target}`, { from: this.opts.version, to: target });
      this.opts.log(`[update] installing ${target}: ${plan.argv.join(' ')}`);
      const { code, output } = await this.run(plan.argv, plan.env);
      if (code !== 0) {
        const tail = output.trim().split('\n').slice(-3).join(' | ');
        this.event(`auto-update to ${target} failed (exit ${code})`, { to: target, code, output: tail });
        return this.note(`install of ${target} failed (exit ${code}): ${tail}`);
      }
      this.opts.log(`[update] ${target} installed; restarting onto it`);
      this.opts.restartDaemon();
      return `updated to ${target}`;
    } finally {
      this.busy = false;
    }
  }

  private note(line: string, log = true): string {
    if (log) this.opts.log(`[update] ${line}`);
    return line;
  }

  private event(message: string, details: Record<string, unknown>): void {
    this.opts.bus.publish({
      timestamp: new Date(this.now()),
      module: 'auto-update',
      category: 'system',
      severity: 'info',
      message,
      details,
    });
  }

  private lastAttempt(): { version: string; at: number } | null {
    try {
      const v = JSON.parse(readFileSync(this.opts.statePath, 'utf8')) as { version?: string; at?: number };
      return v.version && typeof v.at === 'number' ? { version: v.version, at: v.at } : null;
    } catch {
      return null;
    }
  }

  private recordAttempt(version: string): void {
    try {
      writeFileSync(this.opts.statePath, JSON.stringify({ version, at: this.now() }));
    } catch (err) {
      this.opts.log(`[update] could not record attempt: ${(err as Error).message}`);
    }
  }
}
