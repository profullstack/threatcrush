import chalk from 'chalk';
import ora from 'ora';
import { banner, logger } from '../core/logger.js';
import { checkPatches, patchFinding, type Severity } from '../core/patches/index.js';
import { uploadFindings } from './harden.js';

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.cyan,
  info: chalk.gray,
};

/**
 * `threatcrush patches`: OS packages with a security update waiting, and the
 * CVEs each update fixes. Uploads one `os-patches` finding when linked.
 */
export async function patchesCommand(opts: { json?: boolean; upload?: boolean }): Promise<void> {
  if (!opts.json) {
    banner();
    logger.info('Checking OS packages for pending security updates...\n');
  }
  const spinner = opts.json ? null : ora({ text: 'Asking apt and OSV...', color: 'green' }).start();

  const report = await checkPatches();
  const finding = patchFinding(report);

  if (opts.json) {
    console.log(JSON.stringify({ report, finding }, null, 2));
    if (opts.upload !== false) await uploadFindings([finding], true);
    return;
  }

  if (!report.supported) {
    spinner?.warn(report.reason ?? 'Patch status unavailable on this system\n');
    console.log();
    return;
  }
  spinner?.succeed('Patch check complete\n');

  console.log(`  ${chalk.white.bold('System:')} ${report.os} ${chalk.gray(`(${report.ecosystem})`)}`);
  const listsAge = report.lists_updated_at ? report.lists_updated_at.replace('T', ' ').slice(0, 16) + ' UTC' : 'unknown';
  console.log(`  ${chalk.white.bold('Package lists:')} ${report.lists_stale ? chalk.yellow(`${listsAge} (stale; run sudo apt-get update)`) : listsAge}`);
  console.log(`  ${chalk.white.bold('Upgradable:')} ${report.upgradable} package(s), ${report.counts.packages} with security fixes`);
  console.log(chalk.gray('  ' + '─'.repeat(60)));
  console.log();

  if (report.packages.length === 0) {
    console.log(`  ${chalk.green('✓')} No security updates waiting.\n`);
  } else {
    for (const p of report.packages) {
      const sev = SEVERITY_COLOR[p.severity](p.severity.toUpperCase().padEnd(8));
      console.log(`  ${sev} ${chalk.white.bold(p.source)} ${chalk.gray(p.installed)} → ${chalk.green(p.candidate)}`);
      if (p.cves.length > 0) {
        const shown = p.cves.slice(0, 6).map((c) => SEVERITY_COLOR[c.severity](c.id)).join(' ');
        console.log(`           ${shown}${p.cves.length > 6 ? chalk.gray(` +${p.cves.length - 6} more`) : ''}`);
      } else {
        console.log(chalk.gray('           security update; no matching advisory in OSV'));
      }
      if (p.binaries.length > 1 || p.binaries[0] !== p.source) {
        console.log(chalk.gray(`           packages: ${p.binaries.join(', ')}`));
      }
    }
    console.log();
    const c = report.counts;
    console.log(chalk.gray('  ' + '─'.repeat(60)));
    console.log(`  ${chalk.white.bold(`${c.cves} CVE(s) fixed by pending updates:`)} ${chalk.red(`${c.critical} critical`)} ${chalk.red(`${c.high} high`)} ${chalk.yellow(`${c.medium} medium`)} ${chalk.cyan(`${c.low} low`)}`);
    if (finding.recommendation) console.log(`  ${chalk.yellow('Fix:')} ${finding.recommendation}`);
    console.log();
  }
  if (report.osv_error) console.log(chalk.yellow(`  ! CVE lookup incomplete: ${report.osv_error}\n`));

  if (opts.upload !== false) await uploadFindings([finding], false);
}
