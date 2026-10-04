import { statSync } from 'node:fs';
import { join } from 'node:path';
import type { EventEmitter } from 'node:events';
import type { ThreatEvent } from '../types/events.js';
import type { WatchdogSection } from '../types/config.js';
import { WATCHDOG_DIRNAME, WatchdogLog } from '../core/watchdog.js';
import type { WatchdogStatus } from './ipc-protocol.js';

export interface WatchdogServiceOptions {
  bus: Pick<EventEmitter, 'on' | 'off'>;
  config?: WatchdogSection;
  stateDir: string;
  log: (line: string) => void;
  /** Group to share the log with. Default: the gid of /var/log/auth.log when root. */
  shareGid?: number;
  flushMs?: number;
}

export interface WatchdogService {
  status(): WatchdogStatus;
  stop(): void;
}

/**
 * The group allowed to read the attack log: `adm`, found the same way the IPC
 * socket finds it (the group owning /var/log/auth.log). Only when root — a
 * user-mode daemon keeps its log private under ~/.threatcrush.
 */
export function defaultShareGid(): number | undefined {
  const isRoot = process.platform === 'linux' && typeof process.getuid === 'function' && process.getuid() === 0;
  if (!isRoot) return undefined;
  try {
    return statSync('/var/log/auth.log').gid;
  } catch {
    return undefined;
  }
}

/**
 * Watchdog mode, in the daemon: every attack on the bus goes to the triage
 * log, whether or not anyone has a dashboard open. It used to live in the TUI,
 * which meant attacks were only kept while someone was watching.
 */
export function startWatchdog(opts: WatchdogServiceOptions): WatchdogService {
  const dir = opts.config?.dir ?? join(opts.stateDir, WATCHDOG_DIRNAME);
  const base = { dir, logged: 0, answered: 0, errored: 0 };

  if (opts.config?.enabled === false) {
    opts.log('[watchdog] off ([watchdog] enabled = false)');
    return { status: () => ({ enabled: false, ...base }), stop: () => {} };
  }

  let log: WatchdogLog;
  try {
    log = new WatchdogLog(dir, { shareGid: opts.shareGid ?? defaultShareGid() });
  } catch (err) {
    const error = (err as Error).message;
    opts.log(`[watchdog] cannot open ${dir}: ${error}`);
    return { status: () => ({ enabled: false, ...base, error }), stop: () => {} };
  }

  let error: string | undefined;
  const onEvent = (event: ThreatEvent): void => { log.record(event); };
  const flush = (): void => {
    try {
      log.flush();
      error = undefined;
    } catch (err) {
      // Keep recording: a full disk can clear. Say so once per distinct error.
      const message = (err as Error).message;
      if (message !== error) opts.log(`[watchdog] write failed: ${message}`);
      error = message;
    }
  };

  opts.bus.on('event', onEvent);
  const timer = setInterval(flush, opts.flushMs ?? 1000);
  timer.unref?.();
  opts.log(`[watchdog] logging attacks to ${log.file}`);

  return {
    status: () => ({ enabled: true, dir, ...log.stats, ...(error ? { error } : {}) }),
    stop: () => {
      clearInterval(timer);
      opts.bus.off('event', onEvent);
      flush();
    },
  };
}
