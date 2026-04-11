/**
 * ThreatCrush Module SDK
 *
 * Unified type definitions for building ThreatCrush security modules.
 * Merges the CLI module contract with the marketplace boilerplate capabilities.
 *
 * Usage:
 *   import type { ThreatCrushModule, ModuleContext, ThreatEvent } from '@threatcrush/sdk';
 */
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
export interface ModuleLogger {
    debug: (msg: string, ...args: unknown[]) => void;
    info: (msg: string, ...args: unknown[]) => void;
    warn: (msg: string, ...args: unknown[]) => void;
    error: (msg: string, ...args: unknown[]) => void;
}
export interface Alert {
    title: string;
    severity: EventSeverity;
    body?: string;
    event?: ThreatEvent;
}
export interface ModuleConfig {
    [key: string]: unknown;
    enabled?: boolean;
    log_level?: 'debug' | 'info' | 'warn' | 'error';
}
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
/** Normalize a phone number to E.164 format */
export declare function normalizePhone(raw: string): string;
/** Severity label to ANSI color code */
export declare function severityAnsi(severity: EventSeverity): string;
//# sourceMappingURL=index.d.ts.map