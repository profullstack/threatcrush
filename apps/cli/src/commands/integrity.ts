import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import chalk from 'chalk';
import { loadConfig } from '../core/config.js';
import { fileIntegritySettings, FileIntegrityWatch } from '../daemon/workers/file-integrity.js';
import { PATHS, SYSTEM_PATHS, systemDaemonPresent } from '../daemon/paths.js';

interface IntegrityStateFile {
  schema?: number;
  created_at?: string;
  targets?: string[];
  files?: Record<string, string>;
}

function readState(path: string): IntegrityStateFile | null {
  try { return JSON.parse(readFileSync(path, 'utf8')) as IntegrityStateFile; } catch { return null; }
}

function changedCount(baseline: IntegrityStateFile | null, observed: IntegrityStateFile | null): number {
  if (!baseline?.files || !observed?.files) return 0;
  const paths = new Set([...Object.keys(baseline.files), ...Object.keys(observed.files)]);
  let changed = 0;
  for (const path of paths) {
    if ((baseline.files[path] ?? 'missing') !== (observed.files[path] ?? 'missing')) changed++;
  }
  return changed;
}

/** `threatcrush integrity status|rebaseline` — inspect or refresh the local file hashes. */
export async function integrityCommand(action = 'status', opts: { json?: boolean } = {}): Promise<void> {
  const config = loadConfig();
  const settings = fileIntegritySettings(config.file_integrity);
  const systemBaseline = join(SYSTEM_PATHS.stateDir, 'file-integrity-baseline.json');
  const useSystemState = PATHS.mode === 'system' || systemDaemonPresent() || existsSync(systemBaseline);
  const stateDir = useSystemState ? SYSTEM_PATHS.stateDir : PATHS.stateDir;
  const baselinePath = join(stateDir, 'file-integrity-baseline.json');
  const observedPath = join(stateDir, 'file-integrity-observed.json');

  if (action === 'rebaseline') {
    const watch = new FileIntegrityWatch({
      bus: { publish: () => undefined },
      settings,
      baselinePath,
      observedPath,
      log: (line) => { if (!opts.json) console.log(chalk.gray(`  ${line}`)); },
    });
    let result: Awaited<ReturnType<typeof watch.rebaseline>>;
    try {
      result = await watch.rebaseline();
    } catch (error) {
      result = { ok: false, files: 0, reason: (error as Error).message };
    }
    if (opts.json) console.log(JSON.stringify({ action, ...result }, null, 2));
    else if (result.ok) console.log(chalk.green(`  Baseline refreshed for ${result.files} file(s).`));
    else console.error(chalk.red(`  Could not refresh the baseline: ${result.reason}.`));
    if (!result.ok) process.exitCode = 1;
    return;
  }

  if (action !== 'status') {
    console.error(chalk.red(`  Unknown action "${action}". Use status or rebaseline.`));
    process.exitCode = 1;
    return;
  }

  const baseline = readState(baselinePath);
  const observed = readState(observedPath);
  const configuredTargets = [...new Set([...settings.paths, ...settings.canaries])];
  const scopeMatches = !baseline?.targets || (baseline.targets.length === configuredTargets.length &&
    [...baseline.targets].sort().every((path, index) => path === [...configuredTargets].sort()[index]));
  const report = {
    enabled: settings.enabled,
    paths: settings.paths,
    canaries: settings.canaries,
    poll_interval_seconds: settings.pollMs / 1000,
    baseline_at: baseline?.created_at ?? null,
    files_monitored: Object.keys(baseline?.files ?? {}).length,
    changed_files: scopeMatches ? changedCount(baseline, observed) : null,
    scope_matches: scopeMatches,
    baseline_available: baseline !== null,
    state_path: baselinePath,
  };

  if (opts.json) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }
  console.log(`  ${chalk.white.bold('File integrity')} ${report.enabled ? chalk.green('enabled') : chalk.gray('disabled')}`);
  if (report.paths.length) console.log(`  Paths: ${report.paths.join(', ')}`);
  if (report.canaries.length) console.log(`  Canary files: ${report.canaries.join(', ')}`);
  console.log(`  Poll interval: ${report.poll_interval_seconds}s`);
  if (!baseline) {
    console.log(chalk.gray(`  No baseline at ${baselinePath}. Enable monitoring and start the daemon to record one.`));
  } else {
    console.log(`  Baseline: ${report.baseline_at} (${report.files_monitored} files)`);
    if (!report.scope_matches) console.log(chalk.yellow('  Configured paths changed; run rebaseline after reviewing the new scope.'));
    else {
      console.log(`  Current differences: ${report.changed_files}`);
      if (report.changed_files) console.log(chalk.yellow('  Review the daemon event log; refresh only after confirming the changes are expected.'));
    }
  }
  console.log(chalk.gray('  Hashes and file contents stay local. Rebaseline: sudo threatcrush integrity rebaseline'));
}
