import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PATHS, ensureRuntimeDirs } from './paths.js';
import { findRunningDaemon, removePidFile, writePidFile } from './pidfile.js';
import { IpcServer } from './ipc-server.js';
import { ModuleHost } from './module-host.js';
import { AlertDispatcher } from './alerts/index.js';
import { RunsWorker } from './workers/runs-worker.js';
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
