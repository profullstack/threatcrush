/**
 * ThreatCrush Module SDK
 *
 * Unified type definitions for building ThreatCrush security modules.
 * Merges the CLI module contract with the marketplace boilerplate capabilities.
 *
 * Usage:
 *   import type { ThreatCrushModule, ModuleContext, ThreatEvent } from '@threatcrush/sdk';
 */

// ─── Event Types ───

export type EventSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type EventCategory = 'auth' | 'web' | 'network' | 'system' | 'scan' | 'pentest' | 'module';

export interface ThreatEvent {
  id?: number;
  timestamp: Date;
  module: string;
  category: EventCategory;
  severity: EventSeverity;
  message: string;
  source_ip?: string;
  details?: Record<string, unknown>;
}

/** Alias for backward compatibility with boilerplate code */
export type EventPayload = ThreatEvent;

// ─── Logger ───

export interface ModuleLogger {
  debug: (msg: string, ...args: unknown[]) => void;
  info: (msg: string, ...args: unknown[]) => void;
  warn: (msg: string, ...args: unknown[]) => void;
  error: (msg: string, ...args: unknown[]) => void;
}

// ─── Alert ───

export interface Alert {
  title: string;
  severity: EventSeverity;
  body?: string;
  event?: ThreatEvent;
}

// ─── Module Config ───

export interface ModuleConfig {
  [key: string]: unknown;
  enabled?: boolean;
  log_level?: 'debug' | 'info' | 'warn' | 'error';
}

// ─── Module Context ───

export interface ModuleContext {
  /** Module configuration (merged from mod.toml and threatcrushd.conf.d) */
  config: ModuleConfig;

  /** Structured logger scoped to this module */
  logger: ModuleLogger;

  /** Emit a threat event to the daemon event bus */
  emit: (event: ThreatEvent) => void;

  /** Subscribe to event types (e.g. 'log:auth', 'network:scan') */
  subscribe: (eventType: string, handler: (event: ThreatEvent) => void) => void;

  /** Send an alert through the configured alert system */
  alert: (alert: Alert) => void;

  /** Persist module state (backed by SQLite state.db) */
  getState: (key: string) => unknown;

  /** Persist module state (backed by SQLite state.db) */
  setState: (key: string, value: unknown) => void;
}

// ─── Module Interface ───

export interface ThreatCrushModule {
  /** Unique module identifier (matches mod.toml name) */
  name: string;

  /** Semantic version */
  version: string;

  /** Human-readable description */
  description?: string;

  /**
   * Called once when the module is loaded.
   * The context provides config, logger, emit, subscribe, and state APIs.
   */
  init(ctx: ModuleContext): Promise<void>;

  /** Start module execution (begin monitoring, scanning, etc.) */
  start(): Promise<void>;

  /** Graceful shutdown — clean up resources, close connections */
  stop(): Promise<void>;

  /**
   * Called for every event on the daemon bus.
   * Modules can react to events from other modules.
   */
  onEvent?(event: ThreatEvent): Promise<void>;
}

// ─── Module Manifest (from mod.toml) ───

export interface ModuleManifest {
  name: string;
  version: string;
  description: string;
  author?: string;
  license?: string;
  homepage?: string;
  min_threatcrush_version?: string;
  os_support?: string[];
  capabilities?: string[];
}

// ─── Helpers ───

/** Normalize a phone number to E.164 format */
export function normalizePhone(raw: string): string {
  const digits = raw.replace(/[^\d+]/g, '');
  if (digits.startsWith('+')) return digits;
  if (digits.length === 10) return `+1${digits}`;
  return `+${digits}`;
}

/** Severity label to ANSI color code */
export function severityAnsi(severity: EventSeverity): string {
  const codes: Record<EventSeverity, string> = {
    info: '\x1b[32m',    // green
    low: '\x1b[36m',     // cyan
    medium: '\x1b[33m',  // yellow
    high: '\x1b[31m',    // red
    critical: '\x1b[35m', // magenta
  };
  return codes[severity] || '';
}
