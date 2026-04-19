import React, { useEffect, useReducer, useRef } from 'react';
import type { ThreatEvent, EventSeverity } from '../types/events.js';
import type { DaemonStatusReply } from '../daemon/ipc-protocol.js';
import { IpcClient } from '../core/ipc-client.js';

interface ModuleRow { name: string; status: string; events: number; detail?: string }

interface State {
  connected: boolean;
  connectionLabel: string;
  events: ThreatEvent[];
  counters: { events: number; threats: number; modules: number };
  severity: Record<EventSeverity, number>;
  modules: ModuleRow[];
  topSources: Array<{ ip: string; count: number }>;
  timeline: number[];
  daemonStatus: DaemonStatusReply | null;
  paused: boolean;
}

type Action =
  | { type: 'connected'; label: string; status: DaemonStatusReply }
  | { type: 'connection_lost'; label: string }
  | { type: 'event'; event: ThreatEvent }
  | { type: 'tick' }
  | { type: 'modules'; modules: ModuleRow[] }
  | { type: 'top'; top: Array<{ ip: string; count: number }> }
  | { type: 'counters'; counters: { events: number; threats: number } }
  | { type: 'pause' }
  | { type: 'reset' };

const DEMO: ThreatEvent[] = [
  { timestamp: new Date(), module: 'ssh-guard', category: 'auth', severity: 'info', message: 'SSH login accepted for ubuntu', source_ip: '10.0.0.1' },
  { timestamp: new Date(), module: 'log-watcher', category: 'web', severity: 'info', message: 'GET /api/health → 200', source_ip: '172.16.0.50' },
  { timestamp: new Date(), module: 'ssh-guard', category: 'auth', severity: 'high', message: 'Failed SSH login for root', source_ip: '45.33.22.11' },
  { timestamp: new Date(), module: 'log-watcher', category: 'web', severity: 'critical', message: 'Attack [SQLI]: GET /search?q=1%27+OR+1%3D1', source_ip: '185.220.101.44' },
  { timestamp: new Date(), module: 'ssh-guard', category: 'auth', severity: 'high', message: 'Brute force — 6 failures in 45s', source_ip: '45.33.22.11' },
  { timestamp: new Date(), module: 'log-watcher', category: 'web', severity: 'critical', message: 'Attack [PATH_TRAVERSAL]: GET /../../etc/passwd', source_ip: '185.220.101.44' },
  { timestamp: new Date(), module: 'log-watcher', category: 'web', severity: 'medium', message: 'Server error 502: GET /api/users', source_ip: '10.0.0.2' },
  { timestamp: new Date(), module: 'dns-monitor', category: 'network', severity: 'medium', message: 'DNS tunneling suspected: TXT queries', source_ip: '103.44.8.2' },
];

const initialState: State = {
  connected: false,
  connectionLabel: 'connecting...',
  events: [],
  counters: { events: 0, threats: 0, modules: 0 },
  severity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
  modules: [],
  topSources: [],
  timeline: Array(30).fill(0),
  daemonStatus: null,
  paused: false,
};

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'connected':
      return {
        ...state,
        connected: true,
        connectionLabel: action.label,
        daemonStatus: action.status,
        modules: action.status.modules,
        counters: {
          events: action.status.counters.events,
          threats: action.status.counters.threats,
          modules: action.status.modules.length,
        },
      };
    case 'connection_lost':
      return { ...state, connected: false, connectionLabel: action.label };
    case 'event': {
      if (state.paused) return state;
      const events = [...state.events, action.event].slice(-300);
      const severity = { ...state.severity, [action.event.severity]: state.severity[action.event.severity] + 1 };
      const isThreat = action.event.severity === 'medium' || action.event.severity === 'high' || action.event.severity === 'critical';
      return {
        ...state,
        events,
        severity,
        counters: {
          ...state.counters,
          events: state.counters.events + 1,
          threats: state.counters.threats + (isThreat ? 1 : 0),
        },
      };
    }
    case 'tick':
      return { ...state, timeline: [...state.timeline.slice(1), state.events.length] };
    case 'modules':
      return { ...state, modules: action.modules, counters: { ...state.counters, modules: action.modules.length } };
    case 'top':
      return { ...state, topSources: action.top };
    case 'counters':
      return { ...state, counters: { ...state.counters, events: action.counters.events, threats: action.counters.threats } };
    case 'pause':
      return { ...state, paused: !state.paused };
    case 'reset':
      return { ...initialState, connected: state.connected, connectionLabel: state.connectionLabel, daemonStatus: state.daemonStatus, modules: state.modules };
  }
}

const severityColor: Record<EventSeverity, string> = {
  info: 'green',
  low: 'cyan',
  medium: 'yellow',
  high: 'red',
  critical: 'magenta',
};

function fmtTime(d: Date): string {
  return d.toISOString().slice(11, 19);
}

function eventLine(event: ThreatEvent): string {
  const color = severityColor[event.severity];
  const ts = fmtTime(event.timestamp);
  const ip = event.source_ip ? ` (${event.source_ip})` : '';
  const sev = `[${event.severity.toUpperCase()}]`.padEnd(10);
  const mod = `[${event.module}]`.padEnd(14);
  return `{${color}-bold}${ts}{/${color}-bold} {cyan-fg}${mod}{/cyan-fg} {${color}-fg}${sev}{/${color}-fg} ${event.message}${ip}`;
}

function sparklineRow(values: number[], width: number): string {
  const bars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
  const max = Math.max(1, ...values);
  const slice = values.slice(-width);
  return slice.map((v) => bars[Math.min(bars.length - 1, Math.floor((v / max) * (bars.length - 1)))]).join('');
}

function severityBarRow(label: string, count: number, total: number, color: string): string {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  const width = 20;
  const filled = Math.round((pct / 100) * width);
  const bar = `{${color}-fg}${'█'.repeat(filled)}{/}${'·'.repeat(Math.max(0, width - filled))}`;
  return ` {bold}${label.padEnd(8)}{/bold} ${bar} {${color}-fg}${String(count).padStart(4)}{/} ${String(pct).padStart(3)}%`;
}

interface AppProps {
  client: IpcClient | null;
  onExit: () => void;
}

export function App({ client, onExit }: AppProps): React.ReactElement {
  const [state, dispatch] = useReducer(reducer, initialState);
  const screenRef = useRef<{ focus: () => void } | null>(null);

  useEffect(() => {
    if (!client) {
      dispatch({ type: 'connection_lost', label: 'demo mode — no daemon' });
      let i = 0;
      const timer = setInterval(() => {
        const base = DEMO[i % DEMO.length];
        dispatch({ type: 'event', event: { ...base, timestamp: new Date() } });
        i++;
      }, 1800);
      return () => clearInterval(timer);
    }

    let mounted = true;

    // Route pushed IPC events directly into our reducer.
    (client as unknown as { opts: { onEvent?: (e: ThreatEvent) => void } }).opts.onEvent = (event) => {
      if (!mounted) return;
      dispatch({ type: 'event', event });
    };

    client.status()
      .then((status) => { if (mounted) dispatch({ type: 'connected', label: `daemon pid ${status.pid} · v${status.version}`, status }); })
      .catch(() => dispatch({ type: 'connection_lost', label: 'daemon ipc error' }));

    client.subscribe(['event', 'module']).catch(() => {});

    const refresh = setInterval(async () => {
      try {
        const [mods, top, counters] = await Promise.all([
          client.request<ModuleRow[]>('module_list'),
          client.topSources(8),
          client.counters(),
        ]);
        dispatch({ type: 'modules', modules: mods });
        dispatch({ type: 'top', top });
        dispatch({ type: 'counters', counters: { events: counters.total, threats: counters.threats } });
      } catch {
        dispatch({ type: 'connection_lost', label: 'daemon disconnected' });
      }
    }, 2000);

    return () => {
      mounted = false;
      clearInterval(refresh);
    };
  }, [client]);

  useEffect(() => {
    const tick = setInterval(() => dispatch({ type: 'tick' }), 1000);
    return () => clearInterval(tick);
  }, []);

  const totalSeverity = Object.values(state.severity).reduce((a, b) => a + b, 0);
  const feedLines = state.events.slice(-60).map(eventLine).join('\n');
  const spark = sparklineRow(state.timeline, 28);
  const modRows = state.modules.length === 0
    ? '  {gray-fg}(no modules reported){/gray-fg}'
    : state.modules.map((m) => ` ${m.status === 'running' ? '{green-fg}●{/}' : '{cyan-fg}○{/}'} {bold}${m.name.padEnd(16)}{/} {gray-fg}${m.status.padEnd(10)} ${m.events} evt{/}`).join('\n');
  const topRows = state.topSources.length === 0
    ? '  {gray-fg}(no sources yet){/gray-fg}'
    : state.topSources.map((s) => ` {magenta-fg}${s.ip.padEnd(18)}{/} {bold}${String(s.count).padStart(5)}{/}`).join('\n');

  const statusColor = state.connected ? 'green' : 'yellow';
  const statusGlyph = state.connected ? '●' : '○';

  return (
    <element keyable={true} ref={(ref: unknown) => { screenRef.current = ref as { focus: () => void }; }}
      onKey-q={onExit} onKey-escape={onExit} onKey-C-c={onExit}
      onKey-p={() => dispatch({ type: 'pause' })}
      onKey-r={() => dispatch({ type: 'reset' })}
    >
      <box top={0} left={0} width="100%" height={3}
        border={{ type: 'line' }}
        style={{ border: { fg: 'green' } }}
        tags={true}
        content={`  {green-fg}⚡ ThreatCrush{/}  —  Interactive Security Dashboard  {gray-fg}|{/}  {${statusColor}-fg}${statusGlyph} ${state.connectionLabel}{/}${state.paused ? '  {yellow-fg}· PAUSED{/}' : ''}`}
      />

      <box top={3} left={0} width="25%" height={3} border={{ type: 'line' }} style={{ border: { fg: 'green' } }} label=" Events " tags={true}
        content={`  {green-fg}{bold}${state.counters.events}{/bold}{/}`} />
      <box top={3} left="25%" width="25%" height={3} border={{ type: 'line' }} style={{ border: { fg: 'red' } }} label=" Threats " tags={true}
        content={`  {red-fg}{bold}${state.counters.threats}{/bold}{/}`} />
      <box top={3} left="50%" width="25%" height={3} border={{ type: 'line' }} style={{ border: { fg: 'cyan' } }} label=" Modules " tags={true}
        content={`  {cyan-fg}{bold}${state.counters.modules}{/bold}{/}`} />
      <box top={3} left="75%" width="25%" height={3} border={{ type: 'line' }} style={{ border: { fg: statusColor } }} label=" Status " tags={true}
        content={`  {${statusColor}-fg}${statusGlyph} ${state.connected ? 'MONITORING' : 'DEMO'}{/}`} />

      <box top={6} left={0} width="40%" height={10} border={{ type: 'line' }} style={{ border: { fg: 'yellow' } }} label=" Severity " tags={true}
        content={[
          severityBarRow('Info', state.severity.info, totalSeverity, 'green'),
          severityBarRow('Low', state.severity.low, totalSeverity, 'cyan'),
          severityBarRow('Medium', state.severity.medium, totalSeverity, 'yellow'),
          severityBarRow('High', state.severity.high, totalSeverity, 'red'),
          severityBarRow('Critical', state.severity.critical, totalSeverity, 'magenta'),
        ].join('\n')} />

      <box top={6} left="40%" width="30%" height={10} border={{ type: 'line' }} style={{ border: { fg: 'magenta' } }} label=" Top Sources " tags={true}
        content={topRows} />

      <box top={6} left="70%" width="30%" height={10} border={{ type: 'line' }} style={{ border: { fg: 'blue' } }} label=" Events / sec " tags={true}
        content={`\n  {blue-fg}${spark}{/}\n\n  {gray-fg}last ${state.timeline.length}s{/}`} />

      <scrollabletext top={16} left={0} width="70%" height="100%-18"
        border={{ type: 'line' }}
        style={{ border: { fg: 'green' } }}
        label=" Live Event Feed "
        tags={true}
        scrollable={true}
        alwaysScroll={true}
        scrollbar={{ ch: ' ', style: { bg: 'green' } }}
        content={feedLines || '  {gray-fg}(no events yet — waiting for the daemon...){/gray-fg}'} />

      <box top={16} left="70%" width="30%" height="100%-18"
        border={{ type: 'line' }}
        style={{ border: { fg: 'cyan' } }}
        label=" Modules "
        tags={true}
        content={modRows} />

      <box bottom={0} left={0} width="100%" height={3}
        border={{ type: 'line' }}
        style={{ border: { fg: 'green' } }}
        tags={true}
        content=" {green-fg}q{/}:quit  {green-fg}p{/}:pause  {green-fg}r{/}:reset  {gray-fg}|  Ctrl-C exits | daemon over IPC{/}" />
    </element>
  );
}
