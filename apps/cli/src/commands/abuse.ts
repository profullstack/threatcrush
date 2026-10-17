import { existsSync } from 'node:fs';
import chalk from 'chalk';
import { PATHS } from '../daemon/paths.js';
import { loadConfig } from '../core/config.js';
import { currentReports, findReport, markRetracted, type AbuseReportRecord } from '../core/abuse-report-log.js';
import { resolveConfig } from '../daemon/workers/abuse-config.js';

/**
 * `threatcrush abuse` — see, and retract, what the reporter has said about
 * other people's addresses on shared reputation feeds (PRD 0015 R9/R11/R12).
 * Reads the local audit log directly, as `watchdog` reads its own.
 */

export interface AbuseCommonOptions {
  dir?: string;
  json?: boolean;
}

function rows(records: AbuseReportRecord[]): void {
  if (records.length === 0) {
    console.log(chalk.dim('  (none)'));
    return;
  }
  for (const r of records) {
    const when = r.reported_at.replace('T', ' ').slice(0, 19);
    const tag = r.retracted_at
      ? chalk.yellow('retracted')
      : r.mode === 'dry_run'
        ? chalk.cyan('would-report')
        : r.destinations.every((d) => d.ok)
          ? chalk.green('reported')
          : chalk.red('partial/failed');
    console.log(
      `  ${chalk.bold(r.id)}  ${chalk.white(r.ip.padEnd(39))}  ${chalk.dim(when)}  ${tag}  ` +
      `${chalk.dim(`cats ${r.categories.join(',')} · ${r.signals} signals`)}`,
    );
    if (r.destinations.length > 0) {
      console.log(chalk.dim(`      ${r.destinations.map((d) => `${d.destination}: ${d.ok ? 'ok' : 'fail'} (${d.detail})`).join(' · ')}`));
    }
    if (r.retract_note) console.log(chalk.dim(`      retracted: ${r.retract_note}`));
  }
}

export function abuseHistoryCommand(opts: AbuseCommonOptions = {}): void {
  const all = currentReports(opts.dir);
  if (opts.json) {
    console.log(JSON.stringify(all, null, 2));
    return;
  }
  console.log(chalk.bold(`\nAbuse reports (${all.length})\n`));
  rows(all);
  console.log();
}

export function abusePendingCommand(opts: AbuseCommonOptions = {}): void {
  // "Pending" in the audit sense: dry-run entries the reporter judged
  // reportable but did not send, and anything not yet acted on. In live mode
  // this is normally empty — reportable sources are reported immediately.
  const pending = currentReports(opts.dir).filter((r) => r.mode === 'dry_run' && !r.retracted_at);
  if (opts.json) {
    console.log(JSON.stringify(pending, null, 2));
    return;
  }
  console.log(chalk.bold(`\nWould report (${pending.length}) — dry-run, nothing sent\n`));
  rows(pending);
  console.log();
}

export function abuseRetractCommand(id: string, opts: AbuseCommonOptions & { note?: string } = {}): void {
  const existing = findReport(id, opts.dir);
  if (!existing) {
    console.error(chalk.red(`No report with id ${id}.`));
    process.exitCode = 1;
    return;
  }
  const note = opts.note || 'retracted by operator';
  const record = markRetracted(id, note, opts.dir);
  console.log(chalk.yellow(`Retracted ${record?.id} (${record?.ip}).`));
  console.log(
    chalk.dim(
      'Removed from our published feed. AbuseIPDB and StopForumSpam have no delete API — ' +
      'show this record to the upstream to have the report removed by hand.',
    ),
  );
}

export function abuseStatusCommand(opts: AbuseCommonOptions = {}): void {
  const config = loadConfig(existsSync(PATHS.configFile) ? PATHS.configFile : undefined);
  const cfg = resolveConfig(config.abuse_reporter);
  const hasKey = Boolean(cfg.keys.abuseipdb || cfg.keys.stopforumspam);
  const active = cfg.enabled && (cfg.dryRun || hasKey);

  console.log(chalk.bold('\nAbuse reporter\n'));
  console.log(`  status        ${active ? chalk.green('active') : chalk.yellow('inert')}${!cfg.enabled ? chalk.dim(' (disabled)') : !hasKey && !cfg.dryRun ? chalk.dim(' (no API key set)') : ''}`);
  console.log(`  mode          ${cfg.dryRun ? chalk.cyan('dry_run') : chalk.green('live')}`);
  console.log(`  destinations  ${cfg.destinations.join(', ')}`);
  console.log(`  keys          abuseipdb=${cfg.keys.abuseipdb ? 'set' : '—'}  stopforumspam=${cfg.keys.stopforumspam ? 'set' : '—'}`);
  console.log(`  evidence bar  >=${cfg.minCorroboratingSignals} signals + completed handshake, cooling-off ${Math.round(cfg.coolingOffSeconds / 60)}m`);
  console.log(`  rate limits   <=${cfg.maxReportsPerHour}/h, ${cfg.maxPerSourcePerDay}/source/day`);
  const reports = currentReports(opts.dir);
  console.log(`  reported      ${reports.filter((r) => r.mode === 'live' && !r.retracted_at).length} live, ${reports.filter((r) => r.mode === 'dry_run').length} dry-run`);
  if (!hasKey && !cfg.dryRun) {
    console.log(chalk.dim('\n  Set ABUSEIPDB_API_KEY (or [abuse-reporter] abuseipdb_api_key) to begin reporting.'));
  }
  console.log();
}
