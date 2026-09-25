import type { ThreatEvent } from '../types/events.js';

export type IpcRequest =
  | { id: number; method: 'ping' }
  | { id: number; method: 'status' }
  | { id: number; method: 'recent_events'; params: { limit?: number } }
  | { id: number; method: 'top_sources'; params: { limit?: number } }
  | { id: number; method: 'counters' }
  | { id: number; method: 'module_list' }
  | { id: number; method: 'subscribe'; params: { channels: Array<'event' | 'module' | 'firewall'> } }
  | { id: number; method: 'blocklist' }
  // Ban and unban are control methods: they change the host's firewall, so
  // they carry the same root-only token as `shutdown` rather than riding on
  // the adm group's read access.
  | { id: number; method: 'block'; params: { ip: string; reason?: string; ttl?: string; token?: string } }
  | { id: number; method: 'unblock'; params: { ip: string; forget?: boolean; token?: string } }
  // `token` is the root-only daemon control token (TC-33).
  | { id: number; method: 'shutdown'; params?: { token?: string } };

export interface BlockedEntryReply {
  ip: string;
  reason: string;
  blocked_at: number;
  expires_at: number;
  /** Which rung of the Fibonacci ladder this ban came from. */
  strikes: number;
  source: 'auto' | 'manual';
  dry_run: boolean;
}

export interface BlocklistReply {
  entries: BlockedEntryReply[];
  /** Addresses that can never be banned, so the UI can say why a ban failed. */
  protected: string[];
  enabled: boolean;
  dry_run: boolean;
  backend: string;
  min_severity: string;
}

export interface IpcResponse<T = unknown> {
  id: number;
  ok: boolean;
  result?: T;
  error?: string;
}

export interface IpcPush {
  push: 'event' | 'module';
  payload: unknown;
}

export type IpcFrame = IpcRequest | IpcResponse | IpcPush;

export interface DaemonStatusReply {
  pid: number;
  startedAt: string;
  uptimeSeconds: number;
  version: string;
  mode: 'system' | 'user';
  paths: {
    config: string;
    log: string;
    state: string;
    socket: string;
  };
  modules: Array<{ name: string; status: string; events: number }>;
  counters: { events: number; threats: number; alerts: number };
  /**
   * Whether the SQLite state DB opened. When false the daemon still detects
   * and alerts, but everything it serves from disk — `top_sources`,
   * `recent_events`, `counters` — comes back empty. Optional so a client can
   * still read a status reply from an older daemon.
   */
  stateDb?: boolean;
}

export interface EventPush {
  push: 'event';
  payload: ThreatEvent;
}

export interface ModulePush {
  push: 'module';
  payload: { name: string; status: string; detail?: string };
}
