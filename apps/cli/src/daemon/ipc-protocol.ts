import type { ThreatEvent } from '../types/events.js';

export type IpcRequest =
  | { id: number; method: 'ping' }
  | { id: number; method: 'status' }
  | { id: number; method: 'recent_events'; params: { limit?: number } }
  | { id: number; method: 'top_sources'; params: { limit?: number } }
  | { id: number; method: 'counters' }
  | { id: number; method: 'module_list' }
  | { id: number; method: 'subscribe'; params: { channels: Array<'event' | 'module'> } }
  | { id: number; method: 'shutdown' };

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
}

export interface EventPush {
  push: 'event';
  payload: ThreatEvent;
}

export interface ModulePush {
  push: 'module';
  payload: { name: string; status: string; detail?: string };
}
