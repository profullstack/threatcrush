import type { ThreatEvent } from './events.js';
import type { ModuleConfig } from './config.js';

export interface ModuleContext {
  config: ModuleConfig;
  logger: ModuleLogger;
  emit: (event: ThreatEvent) => void;
  getState: (key: string) => unknown;
  setState: (key: string, value: unknown) => void;
}

export interface ModuleLogger {
  debug: (msg: string, ...args: unknown[]) => void;
  info: (msg: string, ...args: unknown[]) => void;
  warn: (msg: string, ...args: unknown[]) => void;
  error: (msg: string, ...args: unknown[]) => void;
}

export interface ThreatCrushModule {
  name: string;
  version: string;
  description?: string;

  init(ctx: ModuleContext): Promise<void>;
  start(): Promise<void>;
  stop(): Promise<void>;
  onEvent?(event: ThreatEvent): Promise<void>;
}

export interface LoadedModule {
  manifest: {
    name: string;
    version: string;
    description: string;
    author: string;
  };
  config: ModuleConfig;
  instance?: ThreatCrushModule;
  status: 'loaded' | 'running' | 'stopped' | 'error';
  eventCount: number;
  path: string;
}
