/**
 * code-scanner — static analysis on codebases.
 *
 * `PRD.md` scopes this module to "vulnerabilities, secrets, misconfigs,
 * dependency CVEs". Those are four different detection models over the same
 * directories, so the module is a thin host and each one is a **subsystem**
 * under `src/`:
 *
 *   deps/      dependency and supply-chain scanning — PRD 0002, implemented
 *   secrets/   hardcoded credential detection — PRD 0003, implemented
 *   sast/      source-level vulnerability analysis — PRD 0004, implemented
 *   config/    misconfiguration checks — not yet built
 *
 * PRD 0002 originally proposed dependency scanning as a standalone
 * `dep-scanner` module and left the boundary as an open question. It is
 * resolved here in favour of folding in: two modules would have walked the
 * same trees, held two inventories of the same packages, and given the
 * operator two path lists to keep in sync — for a user-visible surface
 * (`threatcrush scan --deps`) that was always meant to be one command.
 *
 * What survives the fold is the *internal* separation. `deps/` owns an
 * external advisory database and a per-ecosystem parser surface that will keep
 * growing; none of that belongs in a secrets regex pass.
 *
 * Scope of this release is Discover, Detect and Report for `deps/` only.
 * Remediation is deliberately absent: upgrading a transitive dependency under
 * a running production service is more likely to cause the outage than to
 * prevent one (PRD 0002 Non-Goals).
 */

import type { Alert, ModuleContext, ThreatCrushModule, ThreatEvent } from '@threatcrush/sdk';

import {
  DEPS_DEFAULTS,
  scanDependencies,
  severityRank,
  type DepsOptions,
  type DepsResult,
  type Finding,
} from './deps/index.js';
import {
  SAST_DEFAULTS,
  scanSast,
  type SastOptions,
  type SastResult,
} from './sast/index.js';
import {
  SECRETS_DEFAULTS,
  scanSecrets,
  type SecretsOptions,
  type SecretsResult,
} from './secrets/index.js';

const STATE_REPORTED = 'reported_keys';

const DEFAULTS = {
  scanIntervalSeconds: 6 * 60 * 60,
  minSeverity: 'medium' as Finding['severity'],
  maxAlerts: 25,
};

export interface ScanResult {
  deps: DepsResult | null;
  secrets: SecretsResult | null;
  sast: SastResult | null;
  /** True when any subsystem could not complete — never report "clean". */
  incomplete: boolean;
}

export default class CodeScannerModule implements ThreatCrushModule {
  name = 'code-scanner';
  version = '0.1.0';
  description =
    'Static analysis on codebases — dependency advisories, malicious install scripts and lockfile drift';

  private ctx!: ModuleContext;
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  async init(ctx: ModuleContext): Promise<void> {
    this.ctx = ctx;
    const enabled = [this.depsEnabled() ? 'deps' : null].filter(Boolean);
    ctx.logger.info(
      '[%s] initialized — subsystems: %s; paths: %s',
      this.name,
      enabled.join(', ') || 'none',
      this.depsOptions().paths.join(', '),
    );
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
      this.report(await this.scan());
    } catch (err) {
      // A scanner that dies quietly is worse than one that never ran: the
      // operator keeps believing they are covered.
      this.ctx.logger.error('[%s] scan failed: %s', this.name, String(err));
      this.ctx.emit(
        this.event('scan', 'medium', `code-scanner: scan failed — ${String(err)}`, {
          error: String(err),
        }),
      );
    }
  }

  /** Run every enabled subsystem. */
  async scan(): Promise<ScanResult> {
    const deps = this.depsEnabled() ? await scanDependencies(this.depsOptions()) : null;
    const secrets = this.secretsEnabled() ? await scanSecrets(this.secretsOptions()) : null;
    const sast = this.sastEnabled() ? await scanSast(this.sastOptions()) : null;
    return { deps, secrets, sast, incomplete: Boolean(deps?.incomplete) };
  }

  private depsEnabled(): boolean {
    return this.ctx.config.deps_enabled !== false;
  }

  private secretsEnabled(): boolean {
    return this.ctx.config.secrets_enabled !== false;
  }

  private sastEnabled(): boolean {
    return this.ctx.config.sast_enabled !== false;
  }

  private sastOptions(): SastOptions {
    const cfg = this.ctx.config;
    return {
      paths: this.paths(),
      maxDepth: (cfg.max_depth as number | undefined) ?? SAST_DEFAULTS.maxDepth,
      maxFileBytes: (cfg.sast_max_file_bytes as number | undefined) ?? SAST_DEFAULTS.maxFileBytes,
      vendored: (cfg.sast_vendored as SastOptions['vendored'] | undefined) ?? SAST_DEFAULTS.vendored,
      minConfidence:
        (cfg.sast_min_confidence as SastOptions['minConfidence'] | undefined) ??
        SAST_DEFAULTS.minConfidence,
    };
  }

  private secretsOptions(): SecretsOptions {
    const cfg = this.ctx.config;
    const allow = Array.isArray(cfg.secrets_allow) ? (cfg.secrets_allow as string[]) : [];
    return {
      paths: this.paths(),
      maxDepth: (cfg.max_depth as number | undefined) ?? SECRETS_DEFAULTS.maxDepth,
      maxFileBytes:
        (cfg.secrets_max_file_bytes as number | undefined) ?? SECRETS_DEFAULTS.maxFileBytes,
      entropyEnabled: cfg.secrets_entropy !== false,
      scanGitignored: cfg.secrets_scan_gitignored !== false,
      allow,
    };
  }

  private depsOptions(): DepsOptions {
    const cfg = this.ctx.config;
    return {
      paths: this.paths(),
      maxDepth: (cfg.max_depth as number | undefined) ?? DEPS_DEFAULTS.maxDepth,
      advisories: cfg.deps_advisories !== false,
      installScripts: cfg.deps_install_scripts !== false,
      devDependencies:
        (cfg.deps_dev_dependencies as DepsOptions['devDependencies'] | undefined) ??
        DEPS_DEFAULTS.devDependencies,
      onDegraded: (reason) => {
        this.ctx.logger.warn('[%s] advisory lookup failed: %s', this.name, reason);
        this.ctx.emit(
          this.event('scan', 'low', 'code-scanner: advisory lookup unavailable', { error: reason }),
        );
      },
    };
  }

  private report(result: ScanResult): void {
    const floor = severityRank(
      (this.ctx.config.min_severity as Finding['severity'] | undefined) ?? DEFAULTS.minSeverity,
    );
    const maxAlerts = (this.ctx.config.max_alerts as number | undefined) ?? DEFAULTS.maxAlerts;
    const reported = new Set(this.readState<string[]>(STATE_REPORTED, []));

    if (result.secrets) this.reportSecrets(result.secrets, floor, maxAlerts, reported);
    if (result.sast) this.reportSast(result.sast, floor, maxAlerts, reported);

    const deps = result.deps;
    if (!deps) {
      this.writeState(STATE_REPORTED, [...reported].slice(-2000));
      return;
    }

    const notable = deps.findings.filter((f) => severityRank(f.severity) >= floor);
    const failed = deps.inventory.roots.filter((r) => r.status === 'failed');

    // Deduplicate per (package, version, advisory) so a vulnerability present
    // for 90 days alerts on discovery, not once per scan for three months.
    for (const finding of notable
      .filter((f) => !reported.has(`${f.package}@${f.version}:${f.id}`))
      .slice(0, maxAlerts)) {
      const headline = `code-scanner: ${finding.package}@${finding.version} — ${finding.id}`;
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

    for (const verdict of deps.scripts
      .filter(
        (v) =>
          v.severity !== 'info' &&
          !reported.has(`script:${v.script.packageName}@${v.script.version}:${v.script.stage}`),
      )
      .slice(0, maxAlerts)) {
      const { packageName, version, stage } = verdict.script;
      const headline = `code-scanner: ${packageName}@${version} ${stage} script looks dangerous`;
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

    for (const entry of deps.drift
      .filter((d) => !reported.has(`drift:${d.name}:${d.locked}->${d.installed}`))
      .slice(0, maxAlerts)) {
      const headline = `code-scanner: ${entry.name} on disk is ${entry.installed}, lockfile says ${entry.locked}`;
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
      const headline = `code-scanner: ${failed.length} project(s) could not be scanned — this is not a clean result`;
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
      '[%s] deps: %d packages across %d root(s) — %d advisories, %d risky scripts, %d drifted%s',
      this.name,
      deps.inventory.packages.length,
      deps.inventory.roots.length,
      notable.length,
      deps.scripts.length,
      deps.drift.length,
      deps.incomplete ? ' — INCOMPLETE, some roots unreadable' : '',
    );
  }

  /**
   * Alert on credentials.
   *
   * Note what is *not* here: the secret. `SecretFinding` carries only a masked
   * preview and a fingerprint, so there is no path by which a raw value reaches
   * an event, an alert body or the log — enforced by a test rather than by
   * care (PRD 0003 R10).
   */
  private reportSecrets(
    secrets: SecretsResult,
    floor: number,
    maxAlerts: number,
    reported: Set<string>,
  ): void {
    const notable = secrets.findings.filter((f) => severityRank(f.severity) >= floor);

    for (const finding of notable
      .filter((f) => !reported.has(`secret:${f.fingerprint}:${f.file}`))
      .slice(0, maxAlerts)) {
      const headline = `code-scanner: ${finding.description} in ${finding.file}`;
      this.ctx.emit(
        this.event('scan', finding.severity, headline, {
          rule: finding.ruleId,
          file: finding.file,
          line: finding.line,
          preview: finding.preview,
          fingerprint: finding.fingerprint,
          verified: finding.verified,
          gitignored: finding.gitignored,
        }),
      );
      this.ctx.alert({
        title: headline,
        severity: finding.severity,
        body: [
          `${finding.file}:${finding.line}  ${finding.ruleId}`,
          `${finding.preview}   ${finding.fingerprint}`,
          finding.verified ? 'checksum: valid' : null,
          finding.gitignored ? 'not in version control' : null,
          '',
          'Rotate the credential. Deleting the file alone is not remediation.',
        ]
          .filter(Boolean)
          .join('\n'),
      } satisfies Alert);
      reported.add(`secret:${finding.fingerprint}:${finding.file}`);
    }

    this.ctx.logger.info(
      '[%s] secrets: %d file(s) scanned, %d finding(s), %d skipped',
      this.name,
      secrets.filesScanned,
      secrets.findings.length,
      secrets.skipped.length,
    );
  }

  /**
   * Alert on dangerous constructs.
   *
   * The confidence is in the alert body, not implied by tone: a `pattern`
   * finding says the construct exists, and the word "vulnerability" is
   * reserved for `contextual` (PRD 0004 R13).
   */
  private reportSast(
    sast: SastResult,
    floor: number,
    maxAlerts: number,
    reported: Set<string>,
  ): void {
    const notable = sast.findings.filter((f) => severityRank(f.severity) >= floor);

    for (const finding of notable
      .filter((f) => !reported.has(`sast:${f.file}:${f.ruleId}:${f.line}`))
      .slice(0, maxAlerts)) {
      const headline = `code-scanner: ${finding.title} in ${finding.file}:${finding.line}`;
      this.ctx.emit(
        this.event('scan', finding.severity, headline, {
          rule: finding.ruleId,
          cwe: finding.cwe,
          file: finding.file,
          line: finding.line,
          confidence: finding.confidence,
          vendored: finding.vendored,
        }),
      );
      this.ctx.alert({
        title: headline,
        severity: finding.severity,
        body: [
          `${finding.file}:${finding.line}  ${finding.ruleId} (${finding.cwe})`,
          finding.excerpt,
          '',
          `confidence: ${finding.confidence}`,
          finding.consequence,
        ].join('\n'),
      } satisfies Alert);
      reported.add(`sast:${finding.file}:${finding.ruleId}:${finding.line}`);
    }

    // A quiet scan full of suppressions is not a clean one.
    this.ctx.logger.info(
      '[%s] sast: %d file(s) scanned, %d finding(s), %d suppression(s)',
      this.name,
      sast.filesScanned,
      sast.findings.length,
      sast.suppressions.length,
    );
  }

  private paths(): string[] {
    const configured = this.ctx.config.paths;
    if (Array.isArray(configured) && configured.length > 0) return configured as string[];
    if (typeof configured === 'string' && configured.trim()) {
      return configured.split(',').map((p) => p.trim());
    }
    return [...DEPS_DEFAULTS.paths];
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

/** Human-readable one-shot summary, used by `threatcrush scan --deps`. */
export function summarize(result: ScanResult): string {
  const deps = result.deps;
  if (!deps) return 'no subsystems enabled';

  const bySeverity = new Map<string, number>();
  for (const finding of deps.findings) {
    bySeverity.set(finding.severity, (bySeverity.get(finding.severity) ?? 0) + 1);
  }

  const lines: string[] = [
    `${deps.inventory.packages.length} packages across ${deps.inventory.roots.length} root(s)`,
    `advisories: ${[...bySeverity.entries()].map(([s, n]) => `${n} ${s}`).join(', ') || 'none'}`,
    `risky install scripts: ${deps.scripts.length}`,
    `lockfile drift: ${deps.drift.length}`,
  ];

  const failed = deps.inventory.roots.filter((r) => r.status === 'failed');
  if (failed.length > 0) {
    lines.push('');
    for (const root of failed) lines.push(`  FAILED ${root.root} — ${root.reason}`);
    lines.push('This result is not a clean bill of health.');
  }

  return lines.join('\n');
}

export * from './deps/index.js';
export * from './sast/index.js';
export * from './secrets/index.js';
