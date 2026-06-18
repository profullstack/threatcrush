import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PATHS, ensureRuntimeDirs } from './paths.js';
import { findRunningDaemon, removePidFile, writePidFile } from './pidfile.js';
import { IpcServer } from './ipc-server.js';
import { ModuleHost } from './module-host.js';
import { AlertDispatcher } from './alerts/index.js';
import { RunsWorker } from './workers/runs-worker.js';
import { RuleEngine } from './rules/engine.js';
import { loadAllRules } from './rules/loader.js';
import { detectFirewallAdapter } from './firewall/adapters.js';
import { RemediationManager } from './firewall/remediation.js';
import { bus } from './event-bus.js';
import { initStateDB, closeDB } from '../core/state.js';
import { loadConfig } from '../core/config.js';
import { captureException, flushTelemetry, initTelemetry } from '../core/telemetry.js';
import type { ThreatEvent } from '../types/events.js';

function readVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8'));
    return pkg.version || '0.0.0';
  } catch {
    return '0.0.0';
  }
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

  // Firewall auto-remediation (PRD 02)
  const firewallAdapter = detectFirewallAdapter();
  const remediation = new RemediationManager(firewallAdapter, bus, (config as any).remediation);
  bus.on('event', (event) => {
    if (event.module !== 'firewall-rules') {
      void remediation.handleDetection(event);
    }
  });
  logLine(`[daemon] firewall remediation active (backend=${firewallAdapter.name}, dry_run=${(config as any).remediation?.dry_run ?? true})`);

  new AlertDispatcher(bus, config);

  const runsWorker = new RunsWorker(bus);
  try {
    await runsWorker.start();
  } catch (err) {
    logLine(`[daemon] runs-worker failed to start: ${(err as Error).message}`);
  }

  const ipc = new IpcServer(version, moduleHost);
  await ipc.start();
  logLine(`[daemon] ipc listening on ${PATHS.socket}`);

  const shutdown = async (signal: string) => {
    logLine(`[daemon] received ${signal}, shutting down`);
    try { remediation.stop(); } catch {}
    try { runsWorker.stop(); } catch {}
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
