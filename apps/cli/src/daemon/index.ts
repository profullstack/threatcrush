import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { PATHS, ensureRuntimeDirs } from './paths.js';
import { findRunningDaemon, removePidFile, writePidFile } from './pidfile.js';
import { IpcServer } from './ipc-server.js';
import { ModuleHost } from './module-host.js';
import { AlertDispatcher } from './alerts/index.js';
import { RunsWorker } from './workers/runs-worker.js';
import { CloudSync } from './workers/cloud-sync.js';
import { RemediationConsumer } from './workers/remediation-consumer.js';
import { AllowlistSync } from './workers/allowlist-sync.js';
import { RuleEngine } from './rules/engine.js';
import { loadAllRules } from './rules/loader.js';
import { detectFirewallAdapter } from './firewall/adapters.js';
import { RemediationManager } from './firewall/remediation.js';
import { remediationSettings } from './firewall/settings.js';
import { bus } from './event-bus.js';
import { initStateDB, closeDB } from '../core/state.js';
import { loadConfig } from '../core/config.js';
import { configureAttackDetection } from '../core/log-parser.js';
import { captureException, flushTelemetry, initTelemetry } from '../core/telemetry.js';
import { currentLink } from '../core/cloud-events.js';
import type { ThreatEvent } from '../types/events.js';
import type { HardeningResult } from '../commands/harden.js';

function readVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8'));
    return pkg.version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/**
 * `threatcrush harden --json`, in a child process. The checks shell out
 * synchronously (find over /etc and /usr among them); run in the daemon they
 * would stall log tailing and bans for as long as they take.
 */
async function runHardeningChecks(): Promise<HardeningResult[]> {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [join(__dirname, 'index.js'), 'harden', '--json', '--no-upload'],
    { timeout: 120_000, maxBuffer: 4 * 1024 * 1024 },
  );
  const parsed = JSON.parse(stdout.slice(stdout.indexOf('{'))) as { findings?: HardeningResult[] };
  return Array.isArray(parsed.findings) ? parsed.findings : [];
}

function logLine(line: string): void {
  try {
    appendFileSync(PATHS.logFile, `${new Date().toISOString()} ${line}\n`);
  } catch {
    // best-effort
  }
}

export async function runDaemon(): Promise<void> {
  if (findRunningDaemon()) {
    console.error(`threatcrushd already running (pid file at ${PATHS.pidFile}).`);
    process.exit(1);
  }

  ensureRuntimeDirs();
  writePidFile();

  await initTelemetry('daemon');
  process.on('uncaughtException', (err) => {
    logLine(`[daemon] uncaughtException: ${err.message}`);
    captureException(err);
  });
  process.on('unhandledRejection', (reason) => {
    logLine(`[daemon] unhandledRejection: ${String(reason)}`);
    captureException(reason);
  });

  const version = readVersion();
  logLine(`[daemon] starting threatcrushd v${version} mode=${PATHS.mode}`);

  try {
    initStateDB(PATHS.stateDb);
  } catch (err) {
    logLine(`[daemon] state db unavailable: ${(err as Error).message}`);
  }

  const config = loadConfig(existsSync(PATHS.configFile) ? PATHS.configFile : undefined);
  configureAttackDetection(config.detection);

  bus.on('event', (event: ThreatEvent) => {
    logLine(`[event] ${event.severity} ${event.module} ${event.message}`);
  });

  const moduleHost = new ModuleHost(bus);
  await moduleHost.start();

  // Detection rule engine (PRD 01)
  const ruleEngine = new RuleEngine((detection) => {
    const event: ThreatEvent = {
      timestamp: new Date(),
      module: 'rule-engine',
      category: (detection.raw_metadata?.category as any) || 'system',
      severity: detection.severity,
      message: `[DETECTION] ${detection.title}`,
      source_ip: detection.source_ip,
      details: {
        rule_id: detection.rule_id,
        description: detection.description,
        username: detection.username,
        ...detection.raw_metadata,
      },
    };
    bus.publish(event);
  });
  ruleEngine.loadRules(loadAllRules());
  bus.on('event', (event) => {
    if (event.module !== 'rule-engine') ruleEngine.evaluate(event);
  });
  logLine(`[daemon] rule engine loaded ${ruleEngine.getRules().length} rules`);
  setInterval(() => ruleEngine.cleanup(), 300_000);

  // Firewall auto-remediation (PRD 02 / PRD 0010)
  const settings = remediationSettings(config.remediation);
  const firewallAdapter = detectFirewallAdapter(config.remediation?.backend ?? 'auto');
  const remediation = new RemediationManager(firewallAdapter, bus, settings);
  bus.on('event', (event) => {
    if (event.module !== 'firewall-rules') {
      void remediation.handleDetection(event);
    }
  });
  const remediationStatus = remediation.status();
  logLine(
    `[daemon] auto-defence ${remediationStatus.enabled ? 'ON' : 'OFF'} ` +
    `(backend=${remediationStatus.backend}, mode=${remediationStatus.dry_run ? 'dry_run' : 'enforce'}, ` +
    `min_severity=${remediationStatus.min_severity}, bans escalate 1m→2m→3m→5m→8m…)`,
  );
  if (remediationStatus.dry_run && firewallAdapter.enforces !== false) {
    logLine('[daemon] dry_run is set in [remediation] — detections will be logged, not blocked');
  }
  if (firewallAdapter.enforces === false) {
    logLine('[daemon] no manageable firewall found (need fail2ban, nftables or iptables) — bans are simulated');
  }

  new AlertDispatcher(bus, config);

  const runsWorker = new RunsWorker(bus);
  try {
    await runsWorker.start();
  } catch (err) {
    logLine(`[daemon] runs-worker failed to start: ${(err as Error).message}`);
  }

  // Dashboard reporting and remote remediation (docs: README "Cloud dashboard").
  let cloudSync: CloudSync | null = null;
  let remediationConsumer: RemediationConsumer | null = null;
  let allowlistSync: AllowlistSync | null = null;
  if (config.cloud?.enabled === false) {
    logLine('[cloud] disabled by [cloud] enabled = false');
  } else {
    const minSeverity = config.cloud?.min_severity ?? 'medium';
    cloudSync = new CloudSync({
      bus,
      version,
      hostname: hostname(),
      minSeverity,
      spoolPath: join(PATHS.stateDir, 'cloud-spool.jsonl'),
      log: logLine,
      ruleModules: new Set(ruleEngine.getRules().flatMap((rule) => rule.source_types)),
      runHardening: runHardeningChecks,
    });
    cloudSync.start();
    remediationConsumer = new RemediationConsumer(remediation, { log: logLine });
    remediationConsumer.start();
    allowlistSync = new AllowlistSync(remediation, { log: logLine });
    allowlistSync.start();
    const link = currentLink();
    logLine(link
      ? `[cloud] reporting as server ${link.serverId} (org ${link.orgId}), detections >= ${minSeverity}`
      : '[cloud] not linked; run `threatcrush login` and `threatcrush servers link` to report to the dashboard');
  }

  const ipc = new IpcServer(version, moduleHost, remediation);
  await ipc.start();
  logLine(`[daemon] ipc listening on ${PATHS.socket}`);

  const shutdown = async (signal: string) => {
    logLine(`[daemon] received ${signal}, shutting down`);
    try { remediation.stop(); } catch {}
    try { runsWorker.stop(); } catch {}
    try { remediationConsumer?.stop(); } catch {}
    try { allowlistSync?.stop(); } catch {}
    try { await cloudSync?.stop(); } catch {}
    try { await moduleHost.stop(); } catch {}
    try { await ipc.stop(); } catch {}
    try { closeDB(); } catch {}
    try { await flushTelemetry(); } catch {}
    removePidFile();
    process.exit(0);
  };

  process.on('SIGINT', () => { void shutdown('SIGINT'); });
  process.on('SIGTERM', () => { void shutdown('SIGTERM'); });
  process.on('SIGHUP', () => { void shutdown('SIGHUP'); });

  // keep-alive
  setInterval(() => {}, 1 << 30);
}

// Note: auto-boot is handled by `src/daemon-entry.ts` so that importing this
// module from the CLI bundle never accidentally starts a daemon.
