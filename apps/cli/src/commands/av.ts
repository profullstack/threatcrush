import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import chalk from 'chalk';
import ora from 'ora';
import { EICAR, RULES, scanBytes, type AvFileResult } from '@threatcrush/av';
import {
  clamInstallHint,
  deleteQuarantined,
  detectClamAV,
  fullScanTargets,
  listQuarantine,
  quarantineDir,
  quarantineFile,
  quickScanTargets,
  restoreQuarantined,
  scanPaths,
  watchTargets,
  type ScanTarget,
} from '@threatcrush/av/node';
import { apiUrl } from '../core/cli-config.js';

/**
 * `threatcrush av` — CrushAV, the free open-source antivirus.
 *
 * Signatures and heuristics run locally; ClamAV adds millions of signatures
 * when installed; hash reputation sends SHA-256 hashes (never files or names)
 * to threatcrush.com unless --offline.
 */

const SIGNATURE_FILE = join(homedir(), '.threatcrush', 'av', 'signatures.txt');

export interface AvScanOptions {
  full?: boolean;
  clamav?: boolean; // commander's --no-clamav sets false
  requireClamav?: boolean;
  offline?: boolean;
  quarantine?: boolean;
  json?: boolean;
  maxSize?: string;
}

const icon = (v: AvFileResult['verdict']) =>
  v === 'malicious' ? chalk.red('✖ MALWARE') : v === 'suspicious' ? chalk.yellow('▲ SUSPICIOUS') : v === 'error' ? chalk.gray('? ERROR') : chalk.green('✓ clean');

export async function avScanCommand(paths: string[], opts: AvScanOptions = {}): Promise<void> {
  let targets: ScanTarget[];
  let label: string;
  if (paths.length) {
    targets = paths.map((p) => ({ path: resolve(p), depth: Infinity }));
    label = paths.join(', ');
  } else if (opts.full) {
    targets = fullScanTargets();
    label = 'full scan (home folder + system startup and temp locations)';
  } else {
    targets = quickScanTargets();
    label = 'quick scan (downloads, desktop, temp and startup locations)';
  }
  const missing = targets.filter((t) => !existsSync(t.path));
  if (paths.length && missing.length) {
    console.error(chalk.red(`  Not found: ${missing.map((m) => m.path).join(', ')}`));
    process.exitCode = 2;
    return;
  }

  const spinner = opts.json ? null : ora({ text: `CrushAV ${label}`, discardStdin: false }).start();
  let lastPaint = 0;
  const report = await scanPaths(targets, {
    clamav: opts.requireClamav ? 'require' : opts.clamav === false ? 'off' : 'auto',
    reputation: !opts.offline,
    lookupEndpoint: `${apiUrl()}/api/av/lookup`,
    signatureFile: SIGNATURE_FILE,
    maxFileBytes: opts.maxSize ? Number(opts.maxSize) * 1048576 : undefined,
    onProgress: (e) => {
      if (!spinner) return;
      if (e.type === 'phase') {
        if (e.phase === 'reputation') spinner.text = `Checking ${e.detail} against known malware and known-good files`;
        if (e.phase === 'clamav') spinner.text = `ClamAV scanning ${e.detail}`;
      } else if (e.type === 'file' && Date.now() - lastPaint > 120) {
        lastPaint = Date.now();
        const short = e.path.length > 70 ? `…${e.path.slice(-69)}` : e.path;
        spinner.text = `${e.scanned} files  ${chalk.gray(short)}`;
      }
    },
  }).catch((e: Error) => {
    spinner?.fail(e.message);
    if (/ClamAV/.test(e.message)) console.error(`  Install it: ${chalk.cyan(clamInstallHint())}`);
    process.exitCode = 2;
    return null;
  });
  if (!report) return;
  spinner?.stop();

  const flagged = report.results.filter((r) => r.verdict === 'malicious' || r.verdict === 'suspicious');
  const quarantined: Array<{ path: string; id?: string; error?: string }> = [];
  if (opts.quarantine) {
    for (const r of flagged.filter((x) => x.verdict === 'malicious')) {
      try {
        const q = await quarantineFile(r.path, r.detections);
        quarantined.push({ path: r.path, id: q.id });
      } catch (e) {
        quarantined.push({ path: r.path, error: (e as Error).message });
      }
    }
  }

  if (opts.json) {
    console.log(JSON.stringify({ ...report, results: flagged, quarantined }, null, 2));
  } else {
    const s = report.summary;
    console.log();
    console.log(`  ${chalk.bold('CrushAV')} ${chalk.gray(label)}`);
    console.log(`  Engines: ${s.engines.join(', ')}${report.clamav?.available ? chalk.gray(` (${report.clamav.version})`) : ''}`);
    if (!report.clamav?.available && opts.clamav !== false) {
      console.log(chalk.gray(`  Tip: install ClamAV for millions more signatures: ${clamInstallHint()}`));
    }
    if (report.clamavError) console.log(chalk.yellow(`  ClamAV error: ${report.clamavError}`));
    console.log();
    for (const r of flagged) {
      console.log(`  ${icon(r.verdict)}  ${r.path}`);
      for (const d of r.detections.filter((x) => x.impact !== 'info')) {
        console.log(`      ${chalk.bold(d.name)} ${chalk.gray(`[${d.engine}: ${d.id}]`)}`);
        console.log(`      ${chalk.gray(d.description)}`);
      }
    }
    for (const q of quarantined) {
      console.log(q.id ? chalk.cyan(`  Quarantined ${q.path} (id ${q.id})`) : chalk.red(`  Could not quarantine ${q.path}: ${q.error}`));
    }
    console.log();
    const line = `  ${s.scanned} files scanned · ${chalk.red(`${s.malicious} malware`)} · ${chalk.yellow(`${s.suspicious} suspicious`)} · ${s.errors} unreadable · ${s.skipped} skipped`;
    console.log(line);
    if (s.malicious && !opts.quarantine) console.log(chalk.gray('  Re-run with --quarantine to move malware somewhere it cannot run (reversible).'));
    if (!s.malicious && !s.suspicious) console.log(chalk.green('  Nothing found.'));
  }
  if (report.summary.malicious > 0) process.exitCode = 1;
}

export async function avStatusCommand(opts: { json?: boolean } = {}): Promise<void> {
  const clam = await detectClamAV();
  const q = await listQuarantine();
  const status = {
    engine: 'CrushAV',
    heuristic_rules: RULES.length,
    custom_signatures: existsSync(SIGNATURE_FILE) ? SIGNATURE_FILE : null,
    clamav: clam,
    reputation_endpoint: `${apiUrl()}/api/av/lookup`,
    quarantine_dir: quarantineDir(),
    quarantined: q.length,
  };
  if (opts.json) {
    console.log(JSON.stringify(status, null, 2));
    return;
  }
  console.log(`  ${chalk.bold('CrushAV')} free, open-source antivirus`);
  console.log(`  Heuristic rules:   ${RULES.length}`);
  console.log(`  ClamAV:            ${clam.available ? chalk.green(`${clam.version} via ${clam.mode}`) : chalk.yellow('not installed')}`);
  if (!clam.available) console.log(chalk.gray(`                     ${clamInstallHint()}`));
  console.log(`  Hash reputation:   ${status.reputation_endpoint}`);
  console.log(`  Custom signatures: ${status.custom_signatures ?? chalk.gray(`none (add sha256 lines to ${SIGNATURE_FILE})`)}`);
  console.log(`  Quarantine:        ${q.length} file(s) in ${status.quarantine_dir}`);
}

export async function avQuarantineCommand(action = 'list', id?: string, opts: { to?: string; json?: boolean } = {}): Promise<void> {
  try {
    if (action === 'list') {
      const entries = await listQuarantine();
      if (opts.json) {
        console.log(JSON.stringify(entries, null, 2));
        return;
      }
      if (!entries.length) {
        console.log('  Quarantine is empty.');
        return;
      }
      for (const e of entries) {
        console.log(`  ${chalk.cyan(e.id)}  ${e.originalPath}`);
        console.log(chalk.gray(`      ${e.quarantinedAt} · ${e.detections.map((d) => d.name).join(', ') || 'manual'}`));
      }
      return;
    }
    if (!id) throw new Error(`usage: threatcrush av quarantine ${action} <id>`);
    if (action === 'restore') {
      const dest = await restoreQuarantined(id, opts.to ? resolve(opts.to) : undefined);
      console.log(chalk.yellow(`  Restored to ${dest}. It was quarantined for a reason; scan it again before opening.`));
    } else if (action === 'delete') {
      await deleteQuarantined(id);
      console.log(chalk.green(`  Deleted ${id} permanently.`));
    } else if (action === 'add') {
      const e = await quarantineFile(resolve(id));
      console.log(chalk.cyan(`  Quarantined ${e.originalPath} (id ${e.id})`));
    } else {
      throw new Error(`unknown action "${action}". Use list, add, restore or delete.`);
    }
  } catch (e) {
    console.error(chalk.red(`  ${(e as Error).message}`));
    process.exitCode = 1;
  }
}

/** Real-time protection in the foreground: scan files as they land. */
export async function avWatchCommand(paths: string[], opts: { quarantine?: boolean; offline?: boolean; json?: boolean } = {}): Promise<void> {
  const targets: ScanTarget[] = paths.length ? paths.map((p) => ({ path: resolve(p), depth: Infinity })) : quickScanTargets();
  if (!opts.json) {
    console.log(`  ${chalk.bold('CrushAV')} real-time protection is watching:`);
    for (const t of targets) console.log(chalk.gray(`    ${t.path}`));
    console.log(chalk.gray('  New and changed files are scanned as they arrive. Ctrl+C to stop.'));
  }
  const stop = watchTargets(targets, {
    reputation: !opts.offline,
    lookupEndpoint: `${apiUrl()}/api/av/lookup`,
    onResult: async (r) => {
      let quarantinedId: string | undefined;
      if (opts.quarantine && r.verdict === 'malicious') {
        try {
          quarantinedId = (await quarantineFile(r.path, r.detections)).id;
        } catch {
          /* reported below as not quarantined */
        }
      }
      if (opts.json) {
        console.log(JSON.stringify({ ...r, quarantined: quarantinedId ?? null }));
        return;
      }
      if (r.verdict === 'clean') {
        console.log(chalk.gray(`  ✓ ${r.path}`));
        return;
      }
      console.log(`  ${icon(r.verdict)}  ${r.path}`);
      for (const d of r.detections.filter((x) => x.impact !== 'info')) console.log(`      ${chalk.bold(d.name)} ${chalk.gray(d.description)}`);
      if (quarantinedId) console.log(chalk.cyan(`      Quarantined (id ${quarantinedId}).`));
    },
    onError: (p, e) => {
      if (!opts.json) console.error(chalk.yellow(`  cannot watch/scan ${p}: ${e.message}`));
    },
  });
  await new Promise<void>((done) => {
    const quit = () => {
      stop();
      done();
    };
    process.once('SIGINT', quit);
    process.once('SIGTERM', quit);
  });
}

/** Prove the scanner works without writing a test file to disk. */
export async function avTestCommand(): Promise<void> {
  const r = await scanBytes({ name: 'eicar.com', bytes: new TextEncoder().encode(EICAR) });
  const ok = r.verdict === 'malicious';
  console.log(ok ? chalk.green('  ✓ CrushAV detected the EICAR test file (in memory, nothing written).') : chalk.red('  ✖ EICAR was not detected. Please report this.'));
  const clam = await detectClamAV();
  console.log(clam.available ? chalk.green(`  ✓ ClamAV ready: ${clam.version}`) : chalk.yellow(`  ▲ ClamAV not installed. ${clamInstallHint()}`));
  if (!ok) process.exitCode = 1;
}
