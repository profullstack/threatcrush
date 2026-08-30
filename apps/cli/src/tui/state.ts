import type { EventSeverity, ThreatEvent } from '../types/events.js';
import type { DaemonStatusReply } from '../daemon/ipc-protocol.js';

export interface ModuleRow {
  name: string;
  status: string;
  events: number;
  detail?: string;
}

export interface SourceRow {
  ip: string;
  count: number;
}

/**
 * `searching` is the state the old dashboard never had: it used to decide
 * "daemon or demo" once at startup and then lie for the rest of the session.
 */
export type Connection = 'searching' | 'live' | 'lost';

export interface State {
  connection: Connection;
  connectionLabel: string;
  events: ThreatEvent[];
  counters: { events: number; threats: number; modules: number };
  severity: Record<EventSeverity, number>;
  modules: ModuleRow[];
  topSources: SourceRow[];
  /** Events observed per second, one slot per second, oldest first. */
  timeline: number[];
  /** Events seen since the last `tick`, folded into `timeline` each second. */
  pending: number;
  daemon: DaemonStatusReply | null;
  paused: boolean;
  /** Events held back while paused, replayed on resume. Bounded like the feed. */
  parked: ThreatEvent[];
  /** Rows scrolled back from the newest event. 0 pins to the tail. */
  scrollBack: number;
  startedAt: number;
}

export type Action =
  | { type: 'searching'; label: string }
  | { type: 'connected'; label: string; status: DaemonStatusReply }
  | { type: 'connection_lost'; label: string }
  | { type: 'event'; event: ThreatEvent }
  | { type: 'tick' }
  | { type: 'modules'; modules: ModuleRow[] }
  | { type: 'top'; top: SourceRow[] }
  | { type: 'counters'; counters: { events: number; threats: number } }
  | { type: 'pause' }
  | { type: 'scroll'; delta: number }
  | { type: 'scroll_end' }
  | { type: 'reset' };

export const TIMELINE_SLOTS = 60;
export const FEED_LIMIT = 500;

export const SEVERITIES: EventSeverity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function isThreat(severity: EventSeverity): boolean {
  return severity === 'medium' || severity === 'high' || severity === 'critical';
}

export function initialState(now: number = Date.now()): State {
  return {
    connection: 'searching',
    connectionLabel: 'looking for threatcrushd...',
    events: [],
    counters: { events: 0, threats: 0, modules: 0 },
    severity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
    modules: [],
    topSources: [],
    timeline: Array(TIMELINE_SLOTS).fill(0),
    pending: 0,
    daemon: null,
    paused: false,
    parked: [],
    scrollBack: 0,
    startedAt: now,
  };
}

function accept(state: State, event: ThreatEvent): State {
  const events = [...state.events, event].slice(-FEED_LIMIT);
  return {
    ...state,
    events,
    severity: { ...state.severity, [event.severity]: state.severity[event.severity] + 1 },
    // `pending` is what makes the graph a real rate. The old dashboard plotted
    // `events.length`, which is a buffer that saturates at its own cap and then
    // draws a flat line forever.
    pending: state.pending + 1,
    // Hold the reader's position when they have scrolled back, so an arriving
    // event does not yank the feed out from under them.
    scrollBack: state.scrollBack > 0 ? state.scrollBack + 1 : 0,
  };
}

export function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'searching':
      return { ...state, connection: 'searching', connectionLabel: action.label };

    case 'connected':
      return {
        ...state,
        connection: 'live',
        connectionLabel: action.label,
        daemon: action.status,
        modules: action.status.modules,
        counters: {
          events: action.status.counters.events,
          threats: action.status.counters.threats,
          modules: action.status.modules.length,
        },
      };

    case 'connection_lost':
      return { ...state, connection: 'lost', connectionLabel: action.label, daemon: null };

    case 'event': {
      // Pausing parks events instead of dropping them. The old build discarded
      // everything that arrived while paused, so pausing to read a line cost
      // you every line that followed.
      if (state.paused) {
        return { ...state, parked: [...state.parked, action.event].slice(-FEED_LIMIT) };
      }
      return accept(state, action.event);
    }

    case 'tick': {
      // Counters are owned here and only here. They used to be incremented
      // locally by pushes *and* overwritten by the 2s poll, so the header
      // visibly jittered between two different numbers.
      const timeline = [...state.timeline.slice(1), state.pending];
      return { ...state, timeline, pending: 0 };
    }

    case 'modules':
      return {
        ...state,
        modules: action.modules,
        counters: { ...state.counters, modules: action.modules.length },
      };

    case 'top':
      return { ...state, topSources: action.top };

    case 'counters':
      return {
        ...state,
        counters: { ...state.counters, events: action.counters.events, threats: action.counters.threats },
      };

    case 'pause': {
      if (!state.paused) return { ...state, paused: true };
      // Resuming replays whatever arrived while we were stopped.
      let next: State = { ...state, paused: false, parked: [] };
      for (const event of state.parked) next = accept(next, event);
      return next;
    }

    case 'scroll': {
      const max = Math.max(0, state.events.length - 1);
      return { ...state, scrollBack: Math.min(max, Math.max(0, state.scrollBack + action.delta)) };
    }

    case 'scroll_end':
      return { ...state, scrollBack: 0 };

    case 'reset':
      return {
        ...initialState(state.startedAt),
        connection: state.connection,
        connectionLabel: state.connectionLabel,
        daemon: state.daemon,
        modules: state.modules,
        counters: { ...state.counters, events: 0, threats: 0 },
      };
  }
}

/** Events per second over the trailing `window` seconds. */
export function eventsPerSecond(state: State, window = 10): number {
  const slice = state.timeline.slice(-window);
  if (slice.length === 0) return 0;
  const sum = slice.reduce((a, b) => a + b, 0);
  return sum / slice.length;
}

export function severityTotal(state: State): number {
  return SEVERITIES.reduce((sum, key) => sum + state.severity[key], 0);
}

export function formatUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function formatCount(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}
