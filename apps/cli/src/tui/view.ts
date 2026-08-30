import type { Container, Theme } from '@profullstack/hqtui';
import type { EventSeverity, ThreatEvent } from '../types/events.js';
import { levelColors, severityColors } from './theme.js';
import {
  SEVERITIES,
  eventsPerSecond,
  formatCount,
  formatUptime,
  severityTotal,
  type State,
} from './state.js';

export interface ViewOptions {
  /** Wired by the app so the wheel can scroll the feed. */
  onFeedScroll?: (delta: number) => void;
  demo?: boolean;
}

function clock(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function toLogEntry(event: ThreatEvent) {
  return {
    time: clock(event.timestamp),
    level: event.severity.toUpperCase(),
    message: event.message,
    meta: event.source_ip ? `${event.module} · ${event.source_ip}` : event.module,
  };
}

function connectionBadge(state: State, demo: boolean) {
  if (demo) return { glyph: '◈', label: 'DEMO', color: severityColors.medium };
  if (state.connection === 'live') return { glyph: '●', label: 'LIVE', color: severityColors.info };
  if (state.connection === 'searching') {
    return { glyph: '◌', label: 'SEARCHING', color: severityColors.medium };
  }
  return { glyph: '○', label: 'OFFLINE', color: severityColors.high };
}

function header(ui: Container, state: State, theme: Theme, demo: boolean): void {
  const badge = connectionBadge(state, demo);
  const uptime = state.daemon ? formatUptime(state.daemon.uptimeSeconds) : '—';

  ui.box({ size: 3, border: 'rounded', borderColor: theme.border, padding: [0, 1] }, (box) => {
    box.row({ size: 1 }, (row) => {
      row.text('⚡ THREATCRUSH', { fg: theme.primary, bold: true, size: 16 });
      row.text(`${badge.glyph} ${badge.label}`, { fg: badge.color, bold: true, size: 12 });
      row.text(state.connectionLabel, { fg: theme.muted, size: 'fill' });
      if (state.paused) row.text('⏸ PAUSED', { fg: severityColors.medium, bold: true, size: 10 });
      row.text(`uptime ${uptime}`, { fg: theme.muted, size: 16, align: 'right' });
    });
  });
}

function tile(
  parent: Container,
  theme: Theme,
  opts: { title: string; value: string; color: number; note?: string; spark?: number[] },
): void {
  parent.panel(
    { title: opts.title, size: '1fr', border: 'rounded', borderColor: theme.border, titleColor: theme.muted, padding: [0, 1] },
    (panel) => {
      panel.row({ size: 1 }, (row) => {
        row.text(opts.value, { fg: opts.color, bold: true, size: 'fill' });
        if (opts.note) row.text(opts.note, { fg: theme.muted, size: 12, align: 'right' });
      });
      if (opts.spark && opts.spark.length > 0) {
        panel.sparkline({ values: opts.spark, color: opts.color, size: 1 });
      }
    },
  );
}

function tiles(ui: Container, state: State, theme: Theme): void {
  const eps = eventsPerSecond(state);
  ui.row({ size: 4, gap: 1 }, (row) => {
    tile(row, theme, {
      title: ' EVENTS ',
      value: formatCount(state.counters.events),
      color: theme.primary,
      note: `${state.events.length} buffered`,
    });
    tile(row, theme, {
      title: ' THREATS ',
      value: formatCount(state.counters.threats),
      color: severityColors.high,
      note: state.counters.events > 0
        ? `${Math.round((state.counters.threats / state.counters.events) * 100)}%`
        : '0%',
    });
    tile(row, theme, {
      title: ' MODULES ',
      value: `${state.modules.filter((m) => m.status === 'running').length}/${state.modules.length}`,
      color: theme.accent,
      note: 'active',
    });
    tile(row, theme, {
      title: ' EVENTS/SEC ',
      value: eps.toFixed(eps < 10 ? 2 : 1),
      color: severityColors.medium,
      note: 'last 10s',
      spark: state.timeline.slice(-24),
    });
  });
}

function modulesPanel(parent: Container, state: State, theme: Theme): void {
  parent.panel(
    { title: ' MODULES ', size: 'fill', border: 'rounded', borderColor: theme.border, titleColor: theme.primary,
      footer: state.modules.length > 0
        ? `${state.modules.filter((m) => m.status === 'running').length}/${state.modules.length} active`
        : undefined,
      padding: [0, 1] },
    (panel) => {
      if (state.modules.length === 0) {
        panel.label('no modules reported', { fg: theme.muted });
        return;
      }
      panel.table({
        rows: state.modules,
        header: false,
        columns: [
          {
            key: 'status',
            width: 2,
            render: (m) => (m.status === 'running' ? '●' : '○'),
            color: (m) => (m.status === 'running' ? theme.success : theme.muted),
          },
          { key: 'name', width: 'fill', color: () => theme.foreground },
          {
            key: 'events',
            width: 7,
            align: 'right',
            render: (m) => formatCount(m.events),
            color: (m) => (m.events > 0 ? theme.primary : theme.muted),
          },
        ],
      });
    },
  );
}

function severityPanel(parent: Container, state: State, theme: Theme): void {
  const total = severityTotal(state);
  parent.panel(
    { title: ' SEVERITY ', size: 9, border: 'rounded', borderColor: theme.border, titleColor: theme.primary, padding: [0, 1] },
    (panel) => {
      panel.meters(
        SEVERITIES.map((key: EventSeverity) => ({
          label: key,
          value: total > 0 ? state.severity[key] / total : 0,
          max: 1,
          color: severityColors[key],
          text: String(state.severity[key]),
        })),
        { labelWidth: 9, valueWidth: 6, heat: false },
      );
    },
  );
}

function feedPanel(parent: Container, state: State, theme: Theme, options: ViewOptions): void {
  const following = state.scrollBack === 0;
  parent.panel(
    {
      title: ' LIVE EVENTS ',
      size: '2.4fr',
      border: 'rounded',
      borderColor: state.connection === 'live' ? theme.borderFocused : theme.border,
      titleColor: theme.primary,
      subtitle: following ? undefined : `↑ ${state.scrollBack} back · end to follow`,
      subtitleColor: severityColors.medium,
      padding: [0, 1],
    },
    (panel) => {
      if (state.events.length === 0) {
        panel.spacer(1);
        if (state.connection === 'live') {
          panel.text('Connected. Waiting for the first event...', { fg: theme.muted, align: 'center' });
        } else if (state.connection === 'searching') {
          // Never claim the daemon is missing before we have finished looking:
          // the connect is async, so this frame renders before the answer.
          panel.text('Looking for threatcrushd...', { fg: theme.muted, align: 'center' });
        } else {
          // The thing the old dashboard should have said instead of inventing
          // eight fake attacks and calling it "demo mode".
          panel.text('No daemon is running.', { fg: severityColors.high, bold: true, align: 'center' });
          panel.spacer(1);
          panel.text('Start it to see real traffic:', { fg: theme.muted, align: 'center' });
          panel.text('threatcrush start', { fg: theme.primary, bold: true, align: 'center' });
          panel.spacer(1);
          panel.label('This screen connects by itself the moment it appears.', {
            fg: theme.muted,
            align: 'center',
          });
        }
        return;
      }

      panel.log({
        entries: state.events.map(toLogEntry),
        follow: following,
        fromEnd: state.scrollBack,
        scrollbar: true,
        levelColors,
        timeColor: theme.muted,
        metaColor: theme.muted,
        onScroll: options.onFeedScroll,
      });
    },
  );
}

function threatsPanel(parent: Container, state: State, theme: Theme): void {
  parent.panel(
    { title: ' TOP THREATS ', size: 'fill', border: 'rounded', borderColor: theme.border, titleColor: theme.primary, padding: [0, 1] },
    (panel) => {
      if (state.topSources.length === 0) {
        // Ranking is the one panel that reads from SQLite. Say so when the DB
        // is down, rather than showing an empty list that looks like calm.
        if (state.daemon?.stateDb === false) {
          panel.text('state DB unavailable', { fg: severityColors.medium, bold: true });
          panel.label('ranking + history off', { fg: theme.muted });
          panel.label('threatcrush logs', { fg: theme.muted });
        } else {
          panel.label('no sources yet', { fg: theme.muted });
        }
        return;
      }
      const worst = Math.max(...state.topSources.map((s) => s.count), 1);
      panel.table({
        rows: state.topSources,
        header: false,
        columns: [
          { key: 'ip', width: 'fill', color: () => theme.foreground },
          {
            key: 'count',
            width: 6,
            align: 'right',
            render: (s) => formatCount(s.count),
            // Hotter colour the closer a source is to the worst offender.
            color: (s) =>
              s.count >= worst * 0.66
                ? severityColors.high
                : s.count >= worst * 0.33
                  ? severityColors.medium
                  : theme.muted,
          },
        ],
      });
    },
  );
}

function throughputPanel(parent: Container, state: State, theme: Theme): void {
  parent.panel(
    { title: ' THROUGHPUT ', size: 9, border: 'rounded', borderColor: theme.border, titleColor: theme.primary, padding: [0, 1] },
    (panel) => {
      panel.graph({
        values: state.timeline,
        min: 0,
        fill: true,
        axis: true,
        color: theme.primary,
        mode: 'braille',
      });
    },
  );
}

function footer(ui: Container, state: State, theme: Theme): void {
  ui.statusBar({
    size: 1,
    items: [
      { key: 'q', label: 'quit' },
      { key: 'p', label: state.paused ? 'resume' : 'pause' },
      { key: 'r', label: 'reset' },
      { key: '↑↓', label: 'scroll' },
      { key: 'end', label: 'follow' },
    ],
    right: [
      {
        label: state.paused && state.parked.length > 0 ? `${state.parked.length} held` : '',
        color: severityColors.medium,
      },
      { label: state.daemon ? `v${state.daemon.version} · ${state.daemon.mode}` : 'no daemon', color: theme.muted },
    ].filter((item) => item.label !== ''),
    background: theme.surface,
  });
}

/**
 * The whole screen, as a pure function of state. Nothing here touches a
 * terminal, which is what lets `renderToText` assert on it in tests.
 */
export function renderDashboard(
  ui: Container,
  state: State,
  theme: Theme,
  options: ViewOptions = {},
): void {
  const demo = options.demo ?? false;

  ui.column({ gap: 0, padding: 0 }, (col) => {
    header(col, state, theme, demo);
    tiles(col, state, theme);

    col.row({ size: 'fill', gap: 0 }, (row) => {
      row.column({ size: '1fr' }, (left) => {
        modulesPanel(left, state, theme);
        severityPanel(left, state, theme);
      });

      feedPanel(row, state, theme, options);

      row.column({ size: '1fr' }, (right) => {
        threatsPanel(right, state, theme);
        throughputPanel(right, state, theme);
      });
    });

    footer(col, state, theme);
  });
}
