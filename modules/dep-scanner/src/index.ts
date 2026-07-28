/**
 * dep-scanner — detect vulnerable and malicious dependencies on running
 * servers.
 *
 * Implements PRD 0002. Motivated by two things:
 *
 *  - A general-purpose analyzer reported "0 dependencies, coupling 0/100
 *    (good)" for a 13-package pnpm workspace, because it never resolved the
 *    workspace globs. A productivity tool that does that wastes an afternoon; a
 *    security tool that does it issues a clean bill of health without an
 *    examination.
 *  - `event-stream`, `ua-parser-js` and `node-ipc` were all advisory-clean at
 *    the moment they were installed. Matching versions against a vulnerability
 *    database cannot catch a package that is malicious before anyone has
 *    written the advisory — so this module also reads what install scripts
 *    actually *do*.
 *
 * Scope of this release is Discover, Detect and Report. Remediation is
 * deliberately absent: upgrading a transitive dependency under a running
 * production service is more likely to cause the outage than to prevent one
 * (PRD 0002 Non-Goals). See README, "What this does not do".
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { Alert, ModuleContext, ThreatCrushModule, ThreatEvent } from '@threatcrush/sdk';

import { buildInventory, type Inventory, type RootReport } from './inventory.js';
import { queryAdvisories, severityRank, type Finding } from './osv.js';
import { extractScripts, rankScripts, type ScriptVerdict } from './scripts.js';

const STATE_REPORTED = 'reported_keys';

const DEFAULTS = {
  paths: ['/srv', '/var/www', '/opt'],
  scanIntervalSeconds: 6 * 60 * 60,
  minSeverity: 'medium' as Finding['severity'],
  maxAlerts: 25,
  maxDepth: 4,
};

export interface ScanResult {
  inventory: Inventory;
  findings: Finding[];
  scripts: ScriptVerdict[];
  /** True when any root failed to parse — never report "clean" if set. */
  incomplete: boolean;
}

export default class DepScannerModule implements ThreatCrushModule {
  name = 'dep-scanner';
  version = '0.1.0';
  description =
    'Scans installed dependencies for known advisories, malicious install scripts and lockfile drift';

  private ctx!: ModuleContext;
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  async init(ctx: ModuleContext): Promise<void> {
    this.ctx = ctx;
    const paths = this.paths();
    ctx.logger.info('[%s] initialized — scanning %s', this.name, paths.join(', '));
  }

  async start(): Promise<void> {
    const interval =
      (this.ctx.config.scan_interval_seconds as number | undefined) ?? DEFAULTS.scanIntervalSeconds;

    this.running = true;
    this.ctx.logger.info('[%s] scanning every %ds', this.name, interval);

    void this.tick();
    this.timer = setInterval(() => void this.tick(), interval * 1000);
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.ctx.logger.info('[%s] stopped', this.name);
  }

  private async tick(): Promise<void> {
    if (!this.running) return;

    try {
      const result = await this.scan();
      this.report(result);
    } catch (err) {
      // A scanner that dies quietly is worse than one that never ran: the
      // operator keeps believing they are covered.
      this.ctx.logger.error('[%s] scan failed: %s', this.name, String(err));
      this.ctx.emit(
        this.event('scan', 'medium', `dep-scanner: scan failed — ${String(err)}`, {
          error: String(err),
        }),
      );
    }
  }

  /** Inventory, advisory lookup and script scoring for the configured paths. */
  async scan(): Promise<ScanResult> {
    const inventory = await buildInventory(
      this.paths(),
      (this.ctx.config.max_depth as number | undefined) ?? DEFAULTS.maxDepth,
    );

    const scripts = await this.scanInstallScripts(inventory);

    let findings: Finding[] = [];
    if (inventory.packages.length > 0 && this.ctx.config.advisories_enabled !== false) {
      try {
        findings = await queryAdvisories(
          inventory.packages.map((p) => ({ name: p.name, version: p.version })),
        );
      } catch (err) {
        // Advisory lookup is the one part that needs the network. Losing it
        // must degrade the scan, not void it — and must be visible, because a
        // silent skip looks identical to "nothing found".
        this.ctx.logger.warn('[%s] advisory lookup failed: %s', this.name, String(err));
        this.ctx.emit(
          this.event('scan', 'low', 'dep-scanner: advisory lookup unavailable', {
            error: String(err),
          }),
        );
        inventory.incomplete = true;
      }
    }

    // Dev-only findings are ranked down, never dropped (PRD 0002 R9): a
    // suppressed finding the operator never sees is indistinguishable from one
    // that was missed.
    const devOnly = new Set(
      inventory.packages.filter((p) => p.dev).map((p) => `${p.name}@${p.version}`),
    );
    if (this.ctx.config.dev_dependencies !== 'equal') {
      findings = findings.map((f) =>
        devOnly.has(`${f.package}@${f.version}`) && severityRank(f.severity) > 1
          ? { ...f, severity: demote(f.severity) }
          : f,
      );
    }

    return { inventory, findings, scripts, incomplete: inventory.incomplete };
  }

  /** Read lifecycle scripts out of every installed package and score them. */
  private async scanInstallScripts(inventory: Inventory): Promise<ScriptVerdict[]> {
    if (this.ctx.config.install_scripts === false) return [];

    const scripts = [];
    for (const report of inventory.roots) {
      for (const record of report.packages) {
        if (!record.path.startsWith('node_modules')) continue;
        try {
          const manifest = JSON.parse(
            await readFile(join(report.root, record.path, 'package.json'), 'utf8'),
          ) as { name?: string; version?: string; scripts?: Record<string, string> };
          scripts.push(...extractScripts(manifest, record.name));
        } catch {
          // A package whose manifest cannot be read contributes no scripts;
          // the root's own status already records parse trouble.
        }
      }
    }

    return rankScripts(scripts);
  }

  private report(result: ScanResult): void {
    const floor = severityRank(
      (this.ctx.config.min_severity as Finding['severity'] | undefined) ?? DEFAULTS.minSeverity,
    );
    const reported = new Set(this.readState<string[]>(STATE_REPORTED, []));
    const maxAlerts = (this.ctx.config.max_alerts as number | undefined) ?? DEFAULTS.maxAlerts;

    const notable = result.findings.filter((f) => severityRank(f.severity) >= floor);
    const drift = result.inventory.roots.flatMap((r) =>
      r.drift.map((d) => ({ root: r.root, ...d })),
    );
    const failed = result.inventory.roots.filter((r) => r.status === 'failed');

    // Deduplicate per (package, version, advisory) so a vulnerability present
    // for 90 days alerts on discovery, not 360 times.
    const fresh = notable.filter((f) => !reported.has(`${f.package}@${f.version}:${f.id}`));
    const freshScripts = result.scripts.filter(
      (v) =>
        v.severity !== 'info' &&
        !reported.has(`script:${v.script.packageName}@${v.script.version}:${v.script.stage}`),
    );
    const freshDrift = drift.filter(
      (d) => !reported.has(`drift:${d.name}:${d.locked}->${d.installed}`),
    );

    for (const finding of fresh.slice(0, maxAlerts)) {
      const headline = `dep-scanner: ${finding.package}@${finding.version} — ${finding.id}`;
      this.ctx.emit(this.event('scan', finding.severity, headline, { ...finding }));
      this.ctx.alert({
        title: headline,
        severity: finding.severity,
        body: [
          finding.summary,
          finding.fixedIn ? `Fixed in ${finding.fixedIn}` : 'No fix available yet',
          finding.url,
        ].join('\n'),
      } satisfies Alert);
      reported.add(`${finding.package}@${finding.version}:${finding.id}`);
    }

    for (const verdict of freshScripts.slice(0, maxAlerts)) {
      const { packageName, version, stage } = verdict.script;
      const headline = `dep-scanner: ${packageName}@${version} ${stage} script looks dangerous`;
      this.ctx.emit(
        this.event('scan', verdict.severity, headline, {
          package: packageName,
          version,
          stage,
          score: verdict.score,
          command: verdict.script.command.slice(0, 400),
          signals: verdict.signals,
        }),
      );
      this.ctx.alert({
        title: headline,
        severity: verdict.severity,
        body: verdict.signals.map((s) => `• ${s.message}`).join('\n'),
      } satisfies Alert);
      reported.add(`script:${packageName}@${version}:${stage}`);
    }

    for (const entry of freshDrift.slice(0, maxAlerts)) {
      const headline = `dep-scanner: ${entry.name} on disk is ${entry.installed}, lockfile says ${entry.locked}`;
      this.ctx.emit(this.event('scan', 'high', headline, entry));
      this.ctx.alert({
        title: headline,
        severity: 'high',
        body: 'Installed bytes do not match the resolved lockfile — a manual hotfix, or tampering.',
      } satisfies Alert);
      reported.add(`drift:${entry.name}:${entry.locked}->${entry.installed}`);
    }

    // The honesty requirement (PRD 0002 R6): an unexamined root must be louder
    // than a quiet one, and must never be folded into a clean result.
    if (failed.length > 0 && this.ctx.config.fail_on_unparseable !== false) {
      const headline = `dep-scanner: ${failed.length} project(s) could not be scanned — this is not a clean result`;
      this.ctx.emit(
        this.event('scan', 'medium', headline, {
          roots: failed.map((r) => ({ root: r.root, reason: r.reason })),
        }),
      );
      this.ctx.alert({
        title: headline,
        severity: 'medium',
        body: failed.map((r) => `• ${r.root}: ${r.reason ?? 'unknown reason'}`).join('\n'),
      } satisfies Alert);
    }

    this.writeState(STATE_REPORTED, [...reported].slice(-2000));

    this.ctx.logger.info(
      '[%s] %d packages across %d root(s): %d advisories, %d risky scripts, %d drifted%s',
      this.name,
      result.inventory.packages.length,
      result.inventory.roots.length,
      notable.length,
      result.scripts.length,
      drift.length,
      result.incomplete ? ' — INCOMPLETE, some roots unreadable' : '',
    );
  }

  private paths(): string[] {
    const configured = this.ctx.config.paths;
    if (Array.isArray(configured) && configured.length > 0) return configured as string[];
    if (typeof configured === 'string' && configured.trim()) {
      return configured.split(',').map((p) => p.trim());
    }
    return DEFAULTS.paths;
  }

  private event(
    category: ThreatEvent['category'],
    severity: ThreatEvent['severity'],
    message: string,
    details: Record<string, unknown>,
  ): ThreatEvent {
    return { timestamp: new Date(), module: this.name, category, severity, message, details };
  }

  private readState<T>(key: string, fallback: T): T {
    return (this.ctx.getState(key) as T) ?? fallback;
  }

  private writeState(key: string, value: unknown): void {
    this.ctx.setState(key, value);
  }
}

/** One step down the severity ladder, floored at low. */
export function demote(severity: Finding['severity']): Finding['severity'] {
  const order: Finding['severity'][] = ['info', 'low', 'medium', 'high', 'critical'];
  return order[Math.max(1, order.indexOf(severity) - 1)]!;
}

/** Human-readable one-shot summary, used by `threatcrush scan --deps`. */
export function summarize(result: ScanResult): string {
  const lines: string[] = [];
  const bySeverity = new Map<string, number>();
  for (const finding of result.findings) {
    bySeverity.set(finding.severity, (bySeverity.get(finding.severity) ?? 0) + 1);
  }

  lines.push(
    `${result.inventory.packages.length} packages across ${result.inventory.roots.length} root(s)`,
  );
  lines.push(
    `advisories: ${[...bySeverity.entries()].map(([s, n]) => `${n} ${s}`).join(', ') || 'none'}`,
  );
  lines.push(`risky install scripts: ${result.scripts.length}`);

  const failed = result.inventory.roots.filter((r: RootReport) => r.status === 'failed');
  if (failed.length > 0) {
    lines.push('');
    for (const root of failed) lines.push(`  FAILED ${root.root} — ${root.reason}`);
    lines.push('This result is not a clean bill of health.');
  }

  return lines.join('\n');
}

export * from './inventory.js';
export * from './osv.js';
export * from './scripts.js';
export * from './semver.js';
