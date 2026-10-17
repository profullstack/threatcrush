/**
 * OS package patch status (issue #312, PRD 0019 R1): which installed packages
 * have a security update waiting, and which CVEs that update fixes.
 *
 * "A fix is available" is apt's call, not OSV's. OSV lists every advisory that
 * touches an installed version, including the hundreds of Ubuntu CVEs with no
 * fix released at all (a stock 26.04 box matches ~2,400), so counting OSV hits
 * reports a number nobody can act on. Instead:
 *
 *   1. `apt-get -s dist-upgrade` (a simulation: no root, no lock, no changes)
 *      lists what would be installed and from which pocket. Anything coming
 *      from `-security` is a pending security update.
 *   2. Each such binary package is mapped to its source package, the name
 *      Debian and Ubuntu advisories use.
 *   3. OSV is asked about that source package at the installed version, and a
 *      CVE is kept only when its fixed version, for this exact release, lies
 *      between what is installed and what apt would install.
 *
 * apt's view is only as fresh as its package lists, so the report carries the
 * age of the last `apt update` and says so when it is stale. Nothing here runs
 * `apt update` itself: a monitoring agent does not change the box it watches.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { compareDebianVersions } from './dpkg-version.js';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface PendingPackage {
  /** Binary packages apt would upgrade that come from this source package. */
  binaries: string[];
  source: string;
  installed: string;
  candidate: string;
  /** Highest severity among the CVEs this update fixes; medium when none matched. */
  severity: Severity;
  cves: { id: string; severity: Severity }[];
}

export interface PatchReport {
  supported: boolean;
  /** Why the check could not run, when `supported` is false. */
  reason?: string;
  os: string;
  ecosystem: string | null;
  checked_at: string;
  /** Last successful `apt update`, when it can be told. */
  lists_updated_at: string | null;
  lists_stale: boolean;
  /** Every upgrade apt would make, security or not. */
  upgradable: number;
  packages: PendingPackage[];
  counts: Record<Severity, number> & { cves: number; packages: number };
  /** OSV could not be reached; packages are listed without CVE ids. */
  osv_error?: string;
}

export type ExecLike = (file: string, args: string[]) => Promise<string>;
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface PatchOptions {
  exec?: ExecLike;
  fetchImpl?: FetchLike;
  osRelease?: string;
  /** Directory whose newest `*InRelease`/`*Release` mtime marks the last apt update. */
  aptListsDir?: string;
  now?: Date;
  /** Older package lists than this are reported as stale. */
  staleAfterMs?: number;
}

const OSV_QUERY = 'https://api.osv.dev/v1/query';
const STALE_AFTER_MS = 2 * 86_400_000;
const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const defaultExec: ExecLike = async (file, args) => {
  const { stdout } = await promisify(execFile)(file, args, {
    timeout: 120_000,
    maxBuffer: 32 * 1024 * 1024,
    env: { ...process.env, LC_ALL: 'C' },
  });
  return stdout;
};

/** `/etc/os-release` as key/value pairs, quotes stripped. */
export function parseOsRelease(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const m = /^([A-Z_]+)=(.*)$/.exec(line.trim());
    if (m) out[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
  return out;
}

/**
 * The OSV ecosystem for this release, e.g. `Ubuntu:24.04:LTS` or `Debian:12`,
 * or null for a distribution this check does not support yet.
 */
export function osvEcosystem(os: Record<string, string>): string | null {
  if (os.ID === 'ubuntu' && os.VERSION_ID) {
    return /LTS/.test(os.VERSION ?? '') ? `Ubuntu:${os.VERSION_ID}:LTS` : `Ubuntu:${os.VERSION_ID}`;
  }
  if (os.ID === 'debian' && os.VERSION_ID) return `Debian:${os.VERSION_ID.split('.')[0]}`;
  // Derivatives (Mint, Pop!_OS) use their parent's archive but not its version
  // numbers; guessing the release would match the wrong advisories.
  return null;
}

export interface AptUpgrade {
  name: string;
  installed: string;
  candidate: string;
  security: boolean;
}

/**
 * `Inst` lines of `apt-get -s dist-upgrade`:
 *
 *   Inst openssl [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
 *
 * A package new to the system has no `[installed]` part and is not an upgrade.
 */
export function parseAptSimulation(text: string): AptUpgrade[] {
  const out: AptUpgrade[] = [];
  for (const line of text.split('\n')) {
    const m = /^Inst (\S+) \[([^\]]+)\] \((\S+) ([^[)]*)/.exec(line);
    if (!m) continue;
    const origins = m[4];
    out.push({
      name: m[1],
      installed: m[2],
      candidate: m[3],
      security: /-security\b|Debian-Security/i.test(origins),
    });
  }
  return out;
}

/** `dpkg-query` lines of `binary|source|source-version`. */
export function parseSourceMap(text: string): Map<string, { source: string; version: string }> {
  const out = new Map<string, { source: string; version: string }>();
  for (const line of text.split('\n')) {
    const [binary, source, version] = line.trim().split('|');
    if (binary && source && version) out.set(binary.split(':')[0], { source, version });
  }
  return out;
}

/**
 * Candidate source versions from `apt-cache show pkg=ver …`. A binary built
 * from a differently-versioned source says so as `Source: name (version)`;
 * otherwise the source version is the binary's.
 */
export function parseCandidateSources(text: string): Map<string, { source: string; version: string }> {
  const out = new Map<string, { source: string; version: string }>();
  for (const stanza of text.split(/\n\s*\n/)) {
    const pkg = /^Package: (\S+)/m.exec(stanza)?.[1];
    const version = /^Version: (\S+)/m.exec(stanza)?.[1];
    if (!pkg || !version) continue;
    const src = /^Source: (\S+)(?: \(([^)]+)\))?/m.exec(stanza);
    out.set(`${pkg}=${version}`, { source: src?.[1] ?? pkg, version: src?.[2] ?? version });
  }
  return out;
}

interface OsvRecord {
  id: string;
  upstream?: string[];
  aliases?: string[];
  severity?: { type?: string; score?: string }[];
  database_specific?: { severity?: string };
  affected?: {
    package?: { name?: string; ecosystem?: string };
    ranges?: { type?: string; events?: { introduced?: string; fixed?: string; last_affected?: string }[] }[];
    ecosystem_specific?: { urgency?: string };
  }[];
}

/**
 * Severity of a distro advisory. Ubuntu scores its CVEs as `negligible` to
 * `critical` under severity type "Ubuntu"; Debian carries an urgency per
 * affected package. A record with neither is medium, never dropped.
 */
export function advisorySeverity(rec: OsvRecord, ecosystem: string, source: string): Severity {
  const label = (
    rec.severity?.find((s) => s.type === 'Ubuntu')?.score
    ?? rec.database_specific?.severity
    ?? rec.affected?.find((a) => a.package?.ecosystem === ecosystem && a.package?.name === source)?.ecosystem_specific?.urgency
    ?? ''
  ).toLowerCase();
  if (label === 'negligible' || label === 'unimportant') return 'info';
  if (label === 'moderate') return 'medium';
  if ((SEVERITIES as string[]).includes(label)) return label as Severity;
  return 'medium';
}

/**
 * Whether this pending update fixes the advisory: some `fixed` event for this
 * exact release and source package is newer than what is installed and no
 * newer than what apt would install.
 */
export function fixedByUpdate(
  rec: OsvRecord,
  ecosystem: string,
  source: string,
  installed: string,
  candidate: string,
): boolean {
  for (const a of rec.affected ?? []) {
    if (a.package?.ecosystem !== ecosystem || a.package?.name !== source) continue;
    for (const range of a.ranges ?? []) {
      for (const ev of range.events ?? []) {
        const fixed = ev.fixed;
        if (!fixed) continue;
        if (compareDebianVersions(installed, fixed) < 0 && compareDebianVersions(fixed, candidate) <= 0) return true;
      }
    }
  }
  return false;
}

/** The CVE id to show: the upstream CVE for an `UBUNTU-CVE-…`/`DEBIAN-CVE-…` record. */
function displayId(rec: OsvRecord): string {
  return rec.upstream?.find((u) => u.startsWith('CVE-'))
    ?? rec.aliases?.find((u) => u.startsWith('CVE-'))
    ?? rec.id;
}

async function osvRecords(
  doFetch: FetchLike,
  ecosystem: string,
  source: string,
  version: string,
): Promise<OsvRecord[]> {
  const out: OsvRecord[] = [];
  let pageToken: string | undefined;
  // The kernel's source package carries thousands of records; OSV pages them.
  for (let page = 0; page < 20; page++) {
    const res = await doFetch(OSV_QUERY, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name: source, ecosystem }, version, ...(pageToken ? { page_token: pageToken } : {}) }),
    });
    if (!res.ok) throw new Error(`OSV query for ${source} failed: HTTP ${res.status}`);
    const body = (await res.json()) as { vulns?: OsvRecord[]; next_page_token?: string };
    out.push(...(body.vulns ?? []));
    pageToken = body.next_page_token;
    if (!pageToken) break;
  }
  return out;
}

function newestReleaseMtime(dir: string): Date | null {
  try {
    let newest = 0;
    for (const name of readdirSync(dir)) {
      if (!/Release$/.test(name)) continue;
      newest = Math.max(newest, statSync(join(dir, name)).mtimeMs);
    }
    return newest > 0 ? new Date(newest) : null;
  } catch {
    return null;
  }
}

function emptyCounts(): PatchReport['counts'] {
  return { info: 0, low: 0, medium: 0, high: 0, critical: 0, cves: 0, packages: 0 };
}

export async function checkPatches(opts: PatchOptions = {}): Promise<PatchReport> {
  const exec = opts.exec ?? defaultExec;
  const doFetch = opts.fetchImpl ?? (globalThis.fetch as FetchLike);
  const now = opts.now ?? new Date();
  let osText = opts.osRelease;
  if (osText === undefined) {
    try { osText = readFileSync('/etc/os-release', 'utf-8'); } catch { osText = ''; }
  }
  const os = parseOsRelease(osText);
  const ecosystem = osvEcosystem(os);
  const base: PatchReport = {
    supported: false,
    os: os.PRETTY_NAME ?? os.ID ?? 'unknown',
    ecosystem,
    checked_at: now.toISOString(),
    lists_updated_at: null,
    lists_stale: false,
    upgradable: 0,
    packages: [],
    counts: emptyCounts(),
  };
  if (!ecosystem) {
    return { ...base, reason: `patch status supports Debian and Ubuntu; this is ${base.os}` };
  }

  let simulation: string;
  try {
    simulation = await exec('apt-get', ['-s', '-o', 'Debug::NoLocking=1', 'dist-upgrade']);
  } catch (err) {
    return { ...base, reason: `apt-get simulation failed: ${(err as Error).message.split('\n')[0]}` };
  }

  const listsAt = newestReleaseMtime(opts.aptListsDir ?? '/var/lib/apt/lists');
  const report: PatchReport = {
    ...base,
    supported: true,
    lists_updated_at: listsAt?.toISOString() ?? null,
    lists_stale: !listsAt || now.getTime() - listsAt.getTime() > (opts.staleAfterMs ?? STALE_AFTER_MS),
  };

  const upgrades = parseAptSimulation(simulation);
  report.upgradable = upgrades.length;
  const security = upgrades.filter((u) => u.security);
  if (security.length === 0) return report;

  const installedSources = parseSourceMap(await exec('dpkg-query', [
    '-W', '-f=${Package}|${source:Package}|${source:Version}\n', ...security.map((u) => u.name),
  ]).catch(() => ''));
  const candidateSources = parseCandidateSources(await exec('apt-cache', [
    'show', '--no-all-versions', ...security.map((u) => `${u.name}=${u.candidate}`),
  ]).catch(() => ''));

  const bySource = new Map<string, PendingPackage>();
  for (const u of security) {
    const inst = installedSources.get(u.name) ?? { source: u.name, version: u.installed };
    const cand = candidateSources.get(`${u.name}=${u.candidate}`) ?? { source: inst.source, version: u.candidate };
    const key = `${inst.source}|${inst.version}`;
    const entry = bySource.get(key);
    if (entry) {
      entry.binaries.push(u.name);
      if (compareDebianVersions(cand.version, entry.candidate) > 0) entry.candidate = cand.version;
    } else {
      bySource.set(key, {
        binaries: [u.name], source: inst.source, installed: inst.version,
        candidate: cand.version, severity: 'medium', cves: [],
      });
    }
  }

  for (const pkg of bySource.values()) {
    try {
      const seen = new Set<string>();
      for (const rec of await osvRecords(doFetch, ecosystem, pkg.source, pkg.installed)) {
        if (!fixedByUpdate(rec, ecosystem, pkg.source, pkg.installed, pkg.candidate)) continue;
        const id = displayId(rec);
        if (seen.has(id)) continue;
        seen.add(id);
        pkg.cves.push({ id, severity: advisorySeverity(rec, ecosystem, pkg.source) });
      }
    } catch (err) {
      report.osv_error ??= (err as Error).message;
    }
    pkg.cves.sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.id.localeCompare(b.id));
    if (pkg.cves.length > 0) pkg.severity = pkg.cves[0].severity;
    pkg.binaries.sort();
  }

  report.packages = [...bySource.values()].sort(
    (a, b) => RANK[b.severity] - RANK[a.severity] || b.cves.length - a.cves.length || a.source.localeCompare(b.source),
  );
  const counts = emptyCounts();
  counts.packages = report.packages.length;
  for (const pkg of report.packages) {
    counts.cves += pkg.cves.length;
    for (const cve of pkg.cves) counts[cve.severity]++;
  }
  report.counts = counts;
  return report;
}

/** Worst severity with a fix waiting: the CVEs', or medium for a security update OSV could not name. */
export function worstSeverity(report: PatchReport): Severity | null {
  if (report.packages.length === 0) return null;
  return report.packages.reduce<Severity>((w, p) => (RANK[p.severity] > RANK[w] ? p.severity : w), 'info');
}

export interface PatchFinding {
  key: 'os-patches';
  status: 'pass' | 'warn' | 'fail';
  severity: Severity;
  title: string;
  explanation: string;
  recommendation?: string;
  details: Record<string, unknown>;
}

/**
 * Keeps `details` well under the 16 KB the upload trims metadata to (30
 * packages × 10 CVE ids is about 10 KB); past that the trim would drop the
 * whole package list rather than its tail.
 */
const MAX_DETAIL_PACKAGES = 30;

/**
 * The report as one hardening finding, `os-patches`, so the dashboard's
 * existing findings pipeline (upsert per key, pass resolves it) carries it.
 * Fails on a pending high/critical fix, warns on anything lower or on stale
 * package lists, passes otherwise.
 */
export function patchFinding(report: PatchReport): PatchFinding {
  const details: Record<string, unknown> = {
    kind: 'os-patches',
    supported: report.supported,
    os: report.os,
    ecosystem: report.ecosystem,
    checked_at: report.checked_at,
    lists_updated_at: report.lists_updated_at,
    lists_stale: report.lists_stale,
    upgradable: report.upgradable,
    counts: report.counts,
    packages: report.packages.slice(0, MAX_DETAIL_PACKAGES).map((p) => ({
      source: p.source,
      installed: p.installed,
      candidate: p.candidate,
      severity: p.severity,
      binaries: p.binaries.slice(0, 10),
      cve_count: p.cves.length,
      cves: p.cves.slice(0, 10).map((c) => c.id),
    })),
    ...(report.packages.length > MAX_DETAIL_PACKAGES ? { packages_truncated: report.packages.length } : {}),
    ...(report.osv_error ? { osv_error: report.osv_error } : {}),
  };

  if (!report.supported) {
    return {
      key: 'os-patches', status: 'warn', severity: 'info',
      title: 'OS patch status unavailable',
      explanation: report.reason ?? 'Patch status could not be checked on this system.',
      details,
    };
  }

  const worst = worstSeverity(report);
  const staleNote = report.lists_stale
    ? ` Package lists were last refreshed ${report.lists_updated_at ? report.lists_updated_at.slice(0, 10) : 'never'}, so newer fixes may be missing.`
    : '';
  if (!worst) {
    return {
      key: 'os-patches',
      status: report.lists_stale ? 'warn' : 'pass',
      severity: report.lists_stale ? 'low' : 'high',
      title: report.lists_stale ? 'No pending security updates (package lists stale)' : 'No pending security updates',
      explanation: `apt has no security updates waiting.${staleNote}`,
      recommendation: report.lists_stale ? 'Run `sudo apt-get update` (or enable unattended-upgrades) so fixes are seen.' : undefined,
      details,
    };
  }

  const c = report.counts;
  const parts = [c.critical && `${c.critical} critical`, c.high && `${c.high} high`].filter(Boolean);
  const cveText = c.cves > 0 ? `${c.cves} CVE${c.cves === 1 ? '' : 's'}${parts.length ? ` (${parts.join(', ')})` : ''}` : 'unnamed advisories';
  const top = report.packages.slice(0, 5).map((p) => `${p.source} ${p.installed} → ${p.candidate}`).join('; ');
  return {
    key: 'os-patches',
    status: worst === 'critical' || worst === 'high' ? 'fail' : 'warn',
    severity: worst,
    title: `${c.packages} package${c.packages === 1 ? '' : 's'} with security fixes available: ${cveText}`,
    explanation: `Security updates are waiting for ${c.packages} source package${c.packages === 1 ? '' : 's'}: ${top}${report.packages.length > 5 ? '; …' : ''}.${staleNote}`,
    recommendation: 'Apply them: `sudo apt-get update && sudo apt-get upgrade`, then restart affected services (or reboot for a kernel or libc update).',
    details,
  };
}
