import { writeFileSync } from 'node:fs';
import chalk from 'chalk';
import { HOST_CHECKS, runHostScan, type CheckResult, type HostScanReport } from '../core/host-scan/checks.js';
import { parseSince } from '../core/host-scan/parsers.js';

export interface HostScanCommandOptions {
  json?: boolean;
  since?: string;
  denyKeys?: string;
  checks?: string;
  skipChecks?: string;
  output?: string;
  /** secrets-on-disk: search git histories for committed private keys. */
  deep?: boolean;
  /** secrets-on-disk time budget in seconds. */
  secretsTimeout?: string;
}

const STATUS_STYLE: Record<CheckResult['status'], (s: string) => string> = {
  pass: chalk.green, warn: chalk.yellow, fail: chalk.red.bold, skip: chalk.gray,
};

function list(v?: string): string[] | undefined {
  return v ? v.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
}

export function renderHostScan(report: HostScanReport, maxItems = 25): string {
  const lines: string[] = [];
  lines.push(`  ${chalk.white.bold('Host integrity scan')} ${report.host} (kernel ${report.kernel})${report.root ? '' : chalk.yellow('  not root: partial')}`);
  lines.push('');
  for (const c of report.checks) {
    const tag = STATUS_STYLE[c.status](c.status.toUpperCase().padEnd(4));
    lines.push(`  ${tag}  ${chalk.white(c.title)}  ${chalk.gray(c.reason)}${c.partial ? chalk.yellow(' [partial]') : ''}`);
    for (const item of c.items.slice(0, maxItems)) {
      const mark = item.status === 'fail' ? chalk.red('x') : chalk.yellow('!');
      lines.push(`        ${mark} ${item.message}${item.path ? chalk.gray(`  ${item.path}`) : ''}`);
    }
    if (c.items.length > maxItems) lines.push(chalk.gray(`        ... ${c.items.length - maxItems} more (use --json for all)`));
    if (c.install) lines.push(chalk.gray(`        install: ${c.install}`));
  }
  const s = report.summary;
  lines.push('');
  lines.push(`  ${chalk.green(`${s.pass} pass`)}, ${chalk.yellow(`${s.warn} warn`)}, ${chalk.red(`${s.fail} fail`)}, ${chalk.gray(`${s.skip} skipped`)}  (${(report.duration_ms / 1000).toFixed(1)}s)`);
  if (!report.root && report.skipped.length) {
    lines.push(chalk.yellow(`  Skipped without root: ${report.skipped.map((k) => k.id).join(', ')}. Re-run with sudo for a full scan.`));
  }
  return lines.join('\n');
}

/** `threatcrush scan --host` / `threatcrush host-scan`: local host integrity and rootkit checks. Exit 1 on any fail. */
export async function hostScanCommand(opts: HostScanCommandOptions = {}): Promise<HostScanReport | null> {
  let sinceMs: number;
  try { sinceMs = parseSince(opts.since ?? '7d'); } catch (e) {
    console.error(chalk.red((e as Error).message));
    process.exitCode = 2;
    return null;
  }
  let secretsTimeoutMs: number | undefined;
  if (opts.secretsTimeout !== undefined) {
    const n = Number(opts.secretsTimeout);
    if (!Number.isFinite(n) || n <= 0) {
      console.error(chalk.red(`--secrets-timeout must be a positive number of seconds (got "${opts.secretsTimeout}")`));
      process.exitCode = 2;
      return null;
    }
    secretsTimeoutMs = n * 1000;
  }
  const only = list(opts.checks);
  const skip = list(opts.skipChecks);
  const known = new Set(HOST_CHECKS.map((c) => c.id));
  const unknown = [...(only ?? []), ...(skip ?? [])].filter((id) => !known.has(id));
  if (unknown.length) {
    console.error(chalk.red(`Unknown check(s): ${unknown.join(', ')}. Known: ${[...known].join(', ')}`));
    process.exitCode = 2;
    return null;
  }
  const report = runHostScan({
    sinceMs,
    denyKeysFile: opts.denyKeys,
    deep: opts.deep,
    secretsTimeoutMs,
    log: opts.json ? undefined : (l) => process.stderr.write(chalk.gray(`  ${l}\n`)),
  }, { only, skip });
  const text = opts.json ? JSON.stringify(report, null, 2) : renderHostScan(report);
  if (opts.output) writeFileSync(opts.output, opts.json ? `${text}\n` : `${renderHostScan(report, Infinity).replace(/\x1b\[[0-9;]*m/g, '')}\n`);
  console.log(text);
  if (report.summary.fail > 0) process.exitCode = 1;
  return report;
}
