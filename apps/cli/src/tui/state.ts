import type { EventSeverity, ThreatEvent } from '../types/events.js';
import type { BlockedEntryReply, BlocklistReply, DaemonStatusReply } from '../daemon/ipc-protocol.js';

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

/**
 * Which panel the arrow keys drive. The feed used to own them unconditionally,
 * which left no way to point at a source — and you cannot ban what you cannot
 * point at. Tab cycles.
 */
export type Focus = 'feed' | 'modules' | 'threats' | 'bans';

export const FOCUS_ORDER: Focus[] = ['feed', 'modules', 'threats', 'bans'];

/** A transient line in the status bar: the result of a ban or unban. */
export interface Notice {
  text: string;
  tone: 'ok' | 'error';
  /** Epoch ms after which it stops being shown. */
  until: number;
}

export interface FirewallInfo {
  enabled: boolean;
  dry_run: boolean;
  backend: string;
  min_severity: string;
  /** Set when the daemon means to enforce but cannot, e.g. it is not root. */
  warning?: string;
}

export const NOTICE_MS = 6000;

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
  /** Active bans, newest first, as the daemon reports them. */
  bans: BlockedEntryReply[];
  /** Addresses the daemon will never ban, so the UI can explain a refusal. */
  protectedList: string[];
  firewall: FirewallInfo | null;
  focus: Focus;
  /** Selected row in TOP THREATS and in BANNED respectively. */
  threatIndex: number;
  banIndex: number;
  notice: Notice | null;
  /** Set while a ban/unban is in flight, so the key does not fire twice. */
  busy: boolean;
  /** Selected row in MODULES. */
  moduleIndex: number;
  /**
   * When set, the feed shows only this module. One module can drown out every
   * other: a resolver logging each query put thousands of INFO lines through
   * `user-journal`, and there was no way to look past them.
   */
  moduleFilter: string | null;
  /**
   * Show low-severity 4xx lines in the feed. Off by default: on a box serving
   * paywalled sites they are most of the traffic (a one-request-per-address
   * proxy swarm against x402 routes put ~150k of them through dev2) and they
   * buried every real detection. They still count in SEVERITY; `n` shows them.
   */
  showNoise: boolean;
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
  | { type: 'blocklist'; reply: BlocklistReply }
  | { type: 'focus'; focus: Focus }
  | { type: 'focus_next' }
  | { type: 'select'; delta: number }
  | { type: 'select_at'; index: number }
  | { type: 'notice'; text: string; tone: 'ok' | 'error'; now?: number }
  | { type: 'busy'; busy: boolean }
  | { type: 'toggle_module_filter' }
  | { type: 'clear_module_filter' }
  | { type: 'toggle_noise' }
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
    bans: [],
    protectedList: [],
    firewall: null,
    focus: 'feed',
    threatIndex: 0,
    banIndex: 0,
    notice: null,
    busy: false,
    moduleIndex: 0,
    moduleFilter: null,
    showNoise: false,
  };
}

/** A routine client error: a 4xx the web server answered, at low severity or below. */
export function isNoise(event: ThreatEvent): boolean {
  return (event.severity === 'low' || event.severity === 'info') && /^Client error 4\d\d:/.test(event.message);
}

/** The events the feed should show, honouring the module filter and the noise toggle. */
export function visibleEvents(state: State): ThreatEvent[] {
  return state.events.filter(
    (e) => (!state.moduleFilter || e.module === state.moduleFilter) && (state.showNoise || !isNoise(e)),
  );
}

/** How many buffered events the noise toggle is hiding right now. */
export function hiddenNoise(state: State): number {
  if (state.showNoise) return 0;
  return state.events.filter((e) => (!state.moduleFilter || e.module === state.moduleFilter) && isNoise(e)).length;
}

/** True when `ip` currently has a ban in force. */
export function isBanned(state: State, ip: string): boolean {
  return state.bans.some((b) => b.ip === ip);
}

/**
 * The address the ban/unban keys act on: whichever row is selected in the
 * focused panel. The feed has no selection, so it offers nothing to ban — the
 * source list and the ban list do.
 */
export function selectedIp(state: State): string | null {
  if (state.focus === 'threats') return state.topSources[state.threatIndex]?.ip ?? null;
  if (state.focus === 'bans') return state.bans[state.banIndex]?.ip ?? null;
  return null;
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
      // The tick is also what ages out a ban/unban notice, so the status bar
      // does not keep claiming a result from five minutes ago.
      const notice = state.notice && state.notice.until <= Date.now() ? null : state.notice;
      return { ...state, timeline, pending: 0, notice };
    }

    case 'modules':
      return {
        ...state,
        modules: action.modules,
        counters: { ...state.counters, modules: action.modules.length },
      };

    case 'top': {
      // Keep the selection on the row the operator was pointing at. Ranking is
      // re-polled every two seconds and the list reorders under them; a fixed
      // index would mean the ban key hits a different address than the one on
      // screen when they pressed it.
      const previous = state.topSources[state.threatIndex]?.ip;
      const moved = previous ? action.top.findIndex((s) => s.ip === previous) : -1;
      const threatIndex = moved >= 0
        ? moved
        : Math.min(state.threatIndex, Math.max(0, action.top.length - 1));
      return { ...state, topSources: action.top, threatIndex };
    }

    case 'blocklist': {
      const previous = state.bans[state.banIndex]?.ip;
      const moved = previous ? action.reply.entries.findIndex((b) => b.ip === previous) : -1;
      const banIndex = moved >= 0
        ? moved
        : Math.min(state.banIndex, Math.max(0, action.reply.entries.length - 1));
      return {
        ...state,
        bans: action.reply.entries,
        protectedList: action.reply.protected,
        firewall: {
          enabled: action.reply.enabled,
          dry_run: action.reply.dry_run,
          backend: action.reply.backend,
          min_severity: action.reply.min_severity,
          warning: action.reply.warning,
        },
        banIndex,
      };
    }

    case 'focus':
      return { ...state, focus: action.focus };

    case 'focus_next': {
      const next = FOCUS_ORDER[(FOCUS_ORDER.indexOf(state.focus) + 1) % FOCUS_ORDER.length];
      return { ...state, focus: next };
    }

    case 'select': {
      if (state.focus === 'modules') {
        const max = Math.max(0, state.modules.length - 1);
        return { ...state, moduleIndex: Math.min(max, Math.max(0, state.moduleIndex + action.delta)) };
      }
      if (state.focus === 'threats') {
        const max = Math.max(0, state.topSources.length - 1);
        return { ...state, threatIndex: Math.min(max, Math.max(0, state.threatIndex + action.delta)) };
      }
      if (state.focus === 'bans') {
        const max = Math.max(0, state.bans.length - 1);
        return { ...state, banIndex: Math.min(max, Math.max(0, state.banIndex + action.delta)) };
      }
      return state;
    }

    case 'select_at': {
      // A click lands on a row directly, and focuses the panel it landed in.
      if (state.focus === 'modules') {
        const max = Math.max(0, state.modules.length - 1);
        return { ...state, moduleIndex: Math.min(max, Math.max(0, action.index)) };
      }
      if (state.focus === 'bans') {
        const max = Math.max(0, state.bans.length - 1);
        return { ...state, banIndex: Math.min(max, Math.max(0, action.index)) };
      }
      const max = Math.max(0, state.topSources.length - 1);
      return { ...state, threatIndex: Math.min(max, Math.max(0, action.index)) };
    }

    case 'notice':
      return {
        ...state,
        notice: {
          text: action.text,
          tone: action.tone,
          until: (action.now ?? Date.now()) + NOTICE_MS,
        },
      };

    case 'busy':
      return { ...state, busy: action.busy };

    case 'toggle_module_filter': {
      const name = state.modules[state.moduleIndex]?.name;
      if (!name) return state;
      // Clicking the module already being shown clears the filter, so the same
      // gesture both focuses and un-focuses.
      const moduleFilter = state.moduleFilter === name ? null : name;
      // Filtering changes what "scrolled back" means; go back to following.
      return { ...state, moduleFilter, scrollBack: 0 };
    }

    case 'clear_module_filter':
      return { ...state, moduleFilter: null, scrollBack: 0 };

    case 'toggle_noise':
      return { ...state, showNoise: !state.showNoise, scrollBack: 0 };

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
        // Reset clears the *view*, never the firewall. Bans are the daemon's
        // state, and wiping them from the screen would make the dashboard
        // disagree with the host it is describing.
        bans: state.bans,
        protectedList: state.protectedList,
        firewall: state.firewall,
        focus: state.focus,
        moduleFilter: state.moduleFilter,
        moduleIndex: state.moduleIndex,
        showNoise: state.showNoise,
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
