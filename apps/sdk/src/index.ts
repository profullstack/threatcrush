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

// ─── Detection Schemas (PRD 00) ───

export type DetectionStatus = 'new' | 'acknowledged' | 'resolved';

export interface Detection {
  id?: string;
  organization_id: string;
  server_id: string;
  rule_id?: string;
  severity: EventSeverity;
  title: string;
  description?: string;
  source_ip?: string;
  username?: string;
  raw_metadata?: Record<string, unknown>;
  detected_at: string;
  status: DetectionStatus;
  created_at?: string;
}

export interface DetectionPayload {
  type: 'detection';
  server_id: string;
  rule_id?: string;
  severity: EventSeverity;
  title: string;
  description?: string;
  source_ip?: string;
  username?: string;
  raw_metadata?: Record<string, unknown>;
  detected_at?: string;
}

export interface HeartbeatPayload {
  type: 'heartbeat';
  server_id: string;
  version?: string;
  uptime_seconds?: number;
  modules?: Array<{ name: string; status: string; events: number }>;
}

export type IngestPayload = DetectionPayload | HeartbeatPayload;

// ─── Remediation Schemas (PRD 00/02) ───

export type RemediationActionType = 'block' | 'unblock' | 'allowlist_add' | 'allowlist_remove';
export type RemediationStatus = 'pending' | 'executed' | 'failed' | 'expired' | 'reversed';

export interface RemediationAction {
  id?: string;
  organization_id: string;
  server_id: string;
  detection_id?: string;
  action_type: RemediationActionType;
  target_value: string;
  status: RemediationStatus;
  executed_at?: string;
  expires_at?: string;
  metadata?: Record<string, unknown>;
  created_at?: string;
}

// ─── Hardening Schemas (PRD 00/03) ───

export type HardeningStatus = 'pass' | 'warn' | 'fail' | 'acknowledged' | 'resolved';

export interface HardeningFinding {
  id?: string;
  organization_id: string;
  server_id: string;
  finding_key: string;
  severity: EventSeverity;
  status: HardeningStatus;
  title: string;
  recommendation?: string;
  observed_at?: string;
  resolved_at?: string;
  created_at?: string;
}

// ─── Allowlist Schemas (PRD 00/12) ───

export type AllowlistType = 'ip' | 'cidr' | 'user';

export interface AllowlistEntry {
  id?: string;
  organization_id: string;
  type: AllowlistType;
  value: string;
  note?: string;
  created_at?: string;
}

// ─── Alert Schemas (PRD 00/08) ───

export type AlertDestinationType = 'slack' | 'discord' | 'email' | 'webhook' | 'pagerduty' | 'push';

export interface AlertDestination {
  id?: string;
  organization_id: string;
  name: string;
  type: AlertDestinationType;
  config: Record<string, unknown>;
  enabled: boolean;
  created_at?: string;
}

export interface AlertRule {
  id?: string;
  organization_id: string;
  name: string;
  min_severity: EventSeverity;
  server_scope: string[];
  destination_id: string;
  rate_limit_per_hour?: number;
  enabled: boolean;
  created_at?: string;
}

// ─── Rule Registry (PRD 00/01) ───

export interface RuleRegistryEntry {
  id?: string;
  rule_id: string;
  version: string;
  title: string;
  category: string;
  source_path?: string;
  enabled_by_default: boolean;
  created_at?: string;
}

// ─── Detection Rule Schema (PRD 01) ───

export interface DetectionRule {
  id: string;
  title: string;
  description: string;
  version: string;
  category: EventCategory;
  severity: EventSeverity;
  source_types: string[];
  match: RuleMatch;
  threshold?: number;
  window_seconds?: number;
  cooldown_seconds?: number;
  tags?: string[];
  remediation?: {
    action?: RemediationActionType;
    ttl_seconds?: number;
    description?: string;
  };
  compatibility?: {
    distros?: string[];
    services?: string[];
  };
  enabled?: boolean;
}

export interface RuleMatch {
  field: string;
  operator: 'contains' | 'regex' | 'equals' | 'starts_with' | 'ends_with' | 'gt' | 'lt' | 'gte' | 'lte';
  value: string | number;
  and?: RuleMatch[];
  or?: RuleMatch[];
}

// ─── Hardening Check Schema (PRD 03) ───

export interface HardeningCheck {
  key: string;
  title: string;
  description: string;
  severity: EventSeverity;
  category: string;
  check: () => Promise<HardeningCheckResult>;
}

export interface HardeningCheckResult {
  key: string;
  status: 'pass' | 'warn' | 'fail';
  title: string;
  severity: EventSeverity;
  explanation: string;
  recommendation?: string;
}

// ─── Severity Helpers ───

export const SEVERITY_RANK: Record<EventSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityMeetsMinimum(severity: EventSeverity, minimum: EventSeverity): boolean {
  return (SEVERITY_RANK[severity] ?? 0) >= (SEVERITY_RANK[minimum] ?? 0);
}
