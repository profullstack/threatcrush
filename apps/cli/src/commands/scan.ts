import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import chalk from 'chalk';
import ora from 'ora';
import { banner, logger } from '../core/logger.js';
import type { RunResult, StructuredFinding } from '../core/run-result.js';
import { summarize } from '../core/run-result.js';
import { scanDependencies } from '../scan/dependencies.js';
import { meetsFailThreshold, scanPath } from '../scan/engine.js';
import { buildSarif } from '../scan/sarif.js';
import type { ScanFinding, Severity } from '../scan/types.js';
import { SEVERITY_ORDER } from '../scan/types.js';

export type ScanFormat = 'text' | 'json' | 'sarif';

export interface ScanCommandOptions {
  /**
   * `text` for humans, `sarif` for the Security tab and coverage validators,
   * `json` for anything else. Non-text formats put the payload on stdout (or
   * `--output`) and every human line on stderr, so
   * `threatcrush scan --format sarif > out.sarif` produces a valid file.
   */
  format?: ScanFormat;
  /** Write the machine-readable payload here instead of stdout. */
  output?: string;
  /** Exit non-zero when a finding at or above one of these severities exists. */
  failOn?: readonly Severity[];
  /** Prefix prepended to SARIF URIs when the scan root is not the repo root. */
  pathPrefix?: string;
  /** Print the paths that could not be read, not just the count. */
  verbose?: boolean;
  /**
   * Query OSV.dev for advisories against the resolved lockfile versions.
   * Off by default in the CLI because it is the only part of a scan that
   * needs the network — a CI job should opt in deliberately rather than
   * discover the dependency mid-run.
   */
  dependencies?: boolean;
}

interface ScanOutcome {
  result: RunResult;
  findings: ScanFinding[];
  filesScanned: number;
  unreadable: string[];
  suppressed: number;
  root: string;
}

function readVersion(): string {
  for (const candidate of [
    join(__dirname, '..', 'package.json'),
    join(__dirname, '..', '..', 'package.json'),
  ]) {
    try {
      return (
        (JSON.parse(readFileSync(candidate, 'utf-8')) as { version?: string }).version ?? '0.0.0'
      );
    } catch {
      /* try the next candidate */
    }
  }
  return '0.0.0';
}

const PKG_VERSION = readVersion();

/** Parse `--fail-on critical,high` into severities, rejecting unknown names. */
export function parseFailOn(raw: string | undefined): Severity[] {
  if (!raw) return [];
  const requested = raw
    .split(',')
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean);

  const unknown = requested.filter((name) => !SEVERITY_ORDER.includes(name as Severity));
  if (unknown.length > 0) {
    throw new Error(
      `unknown severity in --fail-on: ${unknown.join(', ')} (expected ${SEVERITY_ORDER.join(', ')})`,
    );
  }
  return requested as Severity[];
}

function toRunResult(
  targetPath: string,
  findings: readonly ScanFinding[],
  filesScanned: number,
): RunResult {
  const structured: StructuredFinding[] = findings.map((finding) => ({
    type: finding.title,
    severity: finding.severity,
    message: finding.message,
    location: `${finding.file}:${finding.line}`,
    details: {
      file: finding.file,
      line: finding.line,
      snippet: finding.excerpt,
      ruleId: finding.ruleId,
      confidence: finding.confidence,
      ...(finding.cwe ? { cwe: finding.cwe } : {}),
    },
  }));
  const counts = summarize(structured);

  return {
    type: 'scan',
    target: targetPath,
    findings: structured,
    severity_summary: counts,
    summary:
      findings.length === 0
        ? `No issues found across ${filesScanned} files`
        : `${findings.length} issue(s): ${counts.critical}C ${counts.high}H ${counts.medium}M ${counts.low}L`,
  };
}

function failedResult(targetPath: string, message: string): RunResult {
  return {
    type: 'scan',
    target: targetPath,
    findings: [],
    severity_summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    summary: `Scan failed: ${message}`,
    error: message,
  };
}

/**
 * Non-interactive scan used by the daemon and the runs worker.
 *
 * Includes dependency advisories, as it always has — the daemon runs on a
 * schedule against a server it can reach the network from, and an advisory
 * published since the last run is the main thing that changed.
 */
export async function runScan(targetPath: string): Promise<RunResult> {
  try {
    const report = scanPath(targetPath);
    const findings = [...report.findings, ...(await scanDependencies(targetPath))];
    return toRunResult(targetPath, findings, report.filesScanned);
  } catch (err) {
    return failedResult(targetPath, (err as Error).message);
  }
}

export async function scanCommand(
  targetPath: string,
  options: ScanCommandOptions = {},
): Promise<RunResult> {
  const format = options.format ?? 'text';
  const machineReadable = format !== 'text';
  // Human output goes to stderr whenever stdout is carrying a payload. A
  // banner in the middle of a SARIF document is exactly how "the scan worked
  // but the pipeline reports zero findings" happens.
  const say = machineReadable
    ? (line: string) => process.stderr.write(`${line}\n`)
    : (line: string) => process.stdout.write(`${line}\n`);

  if (!existsSync(targetPath)) {
    say(chalk.red(`Scan target does not exist: ${targetPath}`));
    process.exitCode = 2;
    return failedResult(targetPath, `no such path: ${targetPath}`);
  }

  if (!machineReadable) {
    banner();
    logger.info(`Scanning ${chalk.white(targetPath)} for security issues...\n`);
  }

  const spinner = machineReadable ? null : ora({ text: 'Scanning files...', color: 'green' }).start();

  let outcome: ScanOutcome;
  try {
    let seen = 0;
    const report = scanPath(targetPath, {
      onFile: () => {
        seen += 1;
        if (spinner) spinner.text = `Scanning files... (${seen} files)`;
      },
    });
    if (options.dependencies) {
      if (spinner) spinner.text = 'Querying OSV.dev for dependency advisories...';
      report.findings.push(...(await scanDependencies(targetPath)));
    }
    outcome = {
      result: toRunResult(targetPath, report.findings, report.filesScanned),
      findings: report.findings,
      filesScanned: report.filesScanned,
      unreadable: report.unreadable,
      suppressed: report.suppressed,
      root: report.root,
    };
  } catch (err) {
    spinner?.fail(`Scan failed: ${(err as Error).message}`);
    process.exitCode = 2;
    return failedResult(targetPath, (err as Error).message);
  }

  spinner?.succeed(`Scanned ${outcome.filesScanned} files\n`);

  if (outcome.unreadable.length > 0) {
    // Surfaced, never swallowed. An unexamined file is not a clean one, and a
    // scanner that hides read failures reports silence as safety.
    say(
      chalk.yellow(
        `  ! ${outcome.unreadable.length} path(s) could not be read and were NOT scanned`,
      ),
    );
    if (options.verbose) {
      for (const path of outcome.unreadable) say(chalk.gray(`      ${path}`));
    }
  }

  if (outcome.suppressed > 0) {
    say(
      chalk.gray(
        `  · ${outcome.suppressed} finding(s) suppressed by inline threatcrush-disable comments`,
      ),
    );
  }

  if (machineReadable) {
    emitMachineReadable(format, outcome, targetPath, options, say);
  } else {
    printHuman(outcome);
  }

  const failOn = options.failOn ?? [];
  if (meetsFailThreshold(outcome.findings, failOn)) {
    say(
      chalk.red(
        `\n  ✗ findings at or above ${[...failOn].join('/')} — failing as requested by --fail-on`,
      ),
    );
    process.exitCode = 1;
  }

  return outcome.result;
}

function emitMachineReadable(
  format: ScanFormat,
  outcome: ScanOutcome,
  targetPath: string,
  options: ScanCommandOptions,
  say: (line: string) => void,
): void {
  const payload =
    format === 'sarif'
      ? buildSarif(outcome.findings, {
          toolVersion: PKG_VERSION,
          pathPrefix: options.pathPrefix,
          // Relative to the working directory, NOT the scan root. `threatcrush
          // scan vulns` from a repo root must emit `vulns/secrets/x.env`, not
          // `secrets/x.env` — the second form matches nothing in the
          // consumer's view of the repository, so every finding lands
          // "outside" whatever it scoped to and a working scan reads as 0%.
          // This is the single most expensive mistake in the whole pipeline
          // and it fails silently. `--path-prefix` covers the remaining case:
          // a scan run from inside the subdirectory it is scanning.
          base: process.cwd(),
          root: resolve(outcome.root),
        })
      : {
          tool: 'threatcrush',
          version: PKG_VERSION,
          target: targetPath,
          filesScanned: outcome.filesScanned,
          unreadable: outcome.unreadable,
          suppressed: outcome.suppressed,
          summary: outcome.result.severity_summary,
          findings: outcome.findings,
        };

  const serialized = `${JSON.stringify(payload, null, 2)}\n`;

  if (options.output) {
    mkdirSync(dirname(resolve(options.output)), { recursive: true });
    writeFileSync(options.output, serialized, 'utf-8');
    say(
      chalk.gray(
        `  ${format.toUpperCase()} written to ${options.output} (${outcome.findings.length} finding(s))`,
      ),
    );
    return;
  }
  process.stdout.write(serialized);
}

function printHuman(outcome: ScanOutcome): void {
  const { findings, filesScanned } = outcome;

  if (findings.length === 0) {
    console.log(chalk.green.bold('  ✓ No security issues found!'));
    console.log();
    return;
  }

  const counts = outcome.result.severity_summary;
  console.log(chalk.white.bold('  Scan Results'));
  console.log(chalk.gray('  ' + '─'.repeat(70)));
  console.log(
    `  ${chalk.red.bold(counts.critical + ' critical')}  ` +
      `${chalk.red(counts.high + ' high')}  ` +
      `${chalk.yellow(counts.medium + ' medium')}  ` +
      `${chalk.gray(counts.low + ' low')}`,
  );
  console.log(chalk.gray('  ' + '─'.repeat(70)));
  console.log();

  for (const finding of findings) {
    const label = finding.severity.toUpperCase();
    const badge =
      finding.severity === 'critical'
        ? chalk.bgRed.white.bold(` ${label} `)
        : finding.severity === 'high'
          ? chalk.red(`[${label}]`)
          : finding.severity === 'medium'
            ? chalk.yellow(`[${label}]`)
            : chalk.gray(`[${label}]`);

    console.log(`  ${badge} ${chalk.white.bold(finding.title)}`);
    console.log(
      `    ${chalk.gray('File:')} ${chalk.cyan(finding.file)}:${chalk.yellow(String(finding.line))}`,
    );
    console.log(`    ${chalk.gray('Info:')} ${finding.message}`);
    if (finding.consequence) {
      console.log(`    ${chalk.gray('Risk:')} ${chalk.dim(finding.consequence)}`);
    }
    if (finding.excerpt) {
      console.log(`    ${chalk.gray('Code:')} ${finding.excerpt}`);
    }
    console.log(
      `    ${chalk.gray('Rule:')} ${chalk.dim(finding.ruleId)}` +
        (finding.cwe ? chalk.dim(` · ${finding.cwe}`) : '') +
        chalk.dim(` · confidence: ${finding.confidence}`),
    );
    console.log();
  }

  console.log(chalk.gray('  ' + '─'.repeat(70)));
  console.log(
    `  ${chalk.white.bold(`${findings.length} issue(s) found`)} across ${filesScanned} files`,
  );
  console.log();
}
