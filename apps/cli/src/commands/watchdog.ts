import { existsSync } from 'node:fs';
import { join } from 'node:path';
import chalk from 'chalk';
import { PATHS } from '../daemon/paths.js';
import {
  WATCHDOG_DIRNAME,
  TRIAGE_STATUSES,
  findFinding,
  findingBrief,
  groupFindings,
  readAttacks,
  readTriage,
  reproCommand,
  setTriage,
  type Finding,
  type Outcome,
  type TriageStatus,
} from '../core/watchdog.js';

export interface WatchdogCommonOptions {
  dir?: string;
}

/**
 * The daemon writes the log: under /var/lib when it runs as root, under
 * ~/.threatcrush when it does not. Prefer the system daemon's, for the same
 * reason the client prefers its socket — it is the one watching the real
 * traffic — and a root daemon shares the directory with `adm`, so an
 * unprivileged `threatcrush watchdog` can read it and record verdicts.
 * A custom `[watchdog] dir` needs `--dir` or THREATCRUSH_WATCHDOG_DIR.
 */
export function resolveWatchdogDir(dir?: string): string {
  if (dir) return dir;
  if (process.env.THREATCRUSH_WATCHDOG_DIR) return process.env.THREATCRUSH_WATCHDOG_DIR;
  const system = join('/var/lib/threatcrush', WATCHDOG_DIRNAME);
  if (existsSync(system)) return system;
  return join(PATHS.stateDir, WATCHDOG_DIRNAME);
}

function load(dir: string): Finding[] {
  return groupFindings(readAttacks(dir), readTriage(dir));
}

const OUTCOME_COLOR: Record<Outcome, (s: string) => string> = {
  answered: chalk.red.bold,
  errored: chalk.magenta.bold,
  unknown: chalk.yellow,
  redirected: chalk.cyan,
  refused: chalk.gray,
};

const TRIAGE_COLOR: Record<TriageStatus, (s: string) => string> = {
  new: chalk.white,
  hole: chalk.red.bold,
  fp: chalk.gray,
  fixed: chalk.green,
};

function where(f: Finding): string {
  if (f.path) return `${f.host ? `${f.host} ` : ''}${f.method ?? ''} ${f.path}`.trim();
  return f.title;
}

export interface WatchdogListOptions extends WatchdogCommonOptions {
  status?: string;
  outcome?: string;
  all?: boolean;
  limit?: string;
  json?: boolean;
}

export function watchdogListCommand(opts: WatchdogListOptions): void {
  const dir = resolveWatchdogDir(opts.dir);
  let findings = load(dir);

  if (opts.status) findings = findings.filter((f) => f.triage.status === opts.status);
  if (opts.outcome) findings = findings.filter((f) => f.outcome === opts.outcome);
  // By default, hide what triage is done with and what was simply refused:
  // the list is a to-do, not an archive. `--all` shows everything.
  if (!opts.all && !opts.status && !opts.outcome) {
    findings = findings.filter((f) => (f.triage.status === 'new' || f.triage.status === 'hole') && f.outcome !== 'refused');
  }
  const limit = opts.limit ? Math.max(1, parseInt(opts.limit, 10) || 50) : 50;

  if (opts.json) {
    console.log(JSON.stringify(findings.slice(0, limit), null, 2));
    return;
  }

  if (findings.length === 0) {
    const empty = existsSync(join(dir, 'attacks.jsonl'))
      ? 'Nothing to triage.' + (opts.all ? '' : ' (refused and triaged findings hidden; --all shows them)')
      : `No watchdog log at ${dir}. The daemon writes it: threatcrush start (or upgrade + restart an older daemon).`;
    console.log(chalk.dim(empty));
    return;
  }

  console.log(chalk.dim(`${dir} · ${findings.length} finding(s)\n`));
  for (const f of findings.slice(0, limit)) {
    const statuses = Object.keys(f.statuses).join(',') || '—';
    console.log(
      `${chalk.bold(f.id)}  ${OUTCOME_COLOR[f.outcome](f.outcome.padEnd(10))} ` +
      `${TRIAGE_COLOR[f.triage.status](f.triage.status.padEnd(5))} ` +
      `${f.severity.padEnd(8)} ${String(f.count).padStart(5)}× ${chalk.dim(statuses.padEnd(9))} ` +
      `${chalk.cyan(f.attack_type ?? f.rule_id ?? f.module)}  ${where(f)}`,
    );
  }
  if (findings.length > limit) console.log(chalk.dim(`\n… ${findings.length - limit} more (--limit)`));
  console.log(chalk.dim('\nthreatcrush watchdog show <id> · brief <id> · mark <id> hole|fp|fixed'));
}

function resolve(dir: string, id: string): Finding {
  const found = findFinding(load(dir), id);
  if (!found) {
    console.error(chalk.red(`No single finding matches "${id}" in ${dir}.`));
    process.exit(1);
  }
  return found;
}

export function watchdogShowCommand(id: string, opts: WatchdogCommonOptions & { json?: boolean }): void {
  const dir = resolveWatchdogDir(opts.dir);
  const f = resolve(dir, id);
  if (opts.json) {
    console.log(JSON.stringify(f, null, 2));
    return;
  }
  console.log(`${chalk.bold(f.id)}  ${OUTCOME_COLOR[f.outcome](f.outcome)}  ${TRIAGE_COLOR[f.triage.status](f.triage.status)}`);
  console.log(`${chalk.cyan(f.attack_type ?? f.rule_id ?? f.module)}  ${where(f)}`);
  console.log(chalk.dim(`${f.count} hit(s) from ${f.source_count} source(s) · ${f.first_seen} → ${f.last_seen}`));
  const statuses = Object.entries(f.statuses).map(([s, n]) => `${s}×${n}`).join(' ');
  if (statuses) console.log(chalk.dim(`status codes: ${statuses}`));
  if (f.triage.note) console.log(`note: ${f.triage.note}`);
  if (f.triage.pr) console.log(`pr:   ${f.triage.pr}`);
  console.log('\nsamples:');
  for (const s of f.samples) {
    console.log(`  ${chalk.dim(s.at)} ${s.ip ?? '?'} → ${s.status ?? '—'}  ${s.method ? `${s.method} ` : ''}${s.url ?? s.message}`);
  }
  console.log(`\nsources: ${f.sources.join(', ')}${f.source_count > f.sources.length ? ` (+${f.source_count - f.sources.length})` : ''}`);
  const repro = f.samples.map(reproCommand).find(Boolean);
  if (repro) console.log(`\nreproduce: ${repro}`);
}

export function watchdogBriefCommand(id: string, opts: WatchdogCommonOptions): void {
  const dir = resolveWatchdogDir(opts.dir);
  process.stdout.write(findingBrief(resolve(dir, id)));
}

export function watchdogMarkCommand(
  id: string,
  status: string,
  opts: WatchdogCommonOptions & { note?: string; pr?: string },
): void {
  if (!TRIAGE_STATUSES.includes(status as TriageStatus)) {
    console.error(chalk.red(`Status must be one of: ${TRIAGE_STATUSES.join(', ')}`));
    process.exit(1);
  }
  const dir = resolveWatchdogDir(opts.dir);
  const f = resolve(dir, id);
  const entry = setTriage(dir, f.id, { status: status as TriageStatus, note: opts.note, pr: opts.pr });
  console.log(`${chalk.bold(f.id)} → ${TRIAGE_COLOR[entry.status](entry.status)}${entry.pr ? ` (${entry.pr})` : ''}`);
}

export function watchdogPathCommand(opts: WatchdogCommonOptions): void {
  console.log(resolveWatchdogDir(opts.dir));
}
