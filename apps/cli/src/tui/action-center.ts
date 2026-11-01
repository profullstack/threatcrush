import { createApp } from '@profullstack/hqtui';
import type { AttackMapData } from '@threatcrush/attack-map';
import { cloudFetch } from '../core/cli-config.js';
import { type EventSeverity } from '../types/events.js';
import { initialState } from './state.js';
import { GeoResolver, mapBody } from './map.js';
import { severityColors, threatcrushTheme } from './theme.js';

interface Organization { id: string; name: string; slug: string }
interface FleetServer {
  id: string;
  name: string;
  org_id: string;
  org_slug: string;
  fleet_id: string | null;
  fleet_name: string | null;
  connection: string;
  last_seen: string | null;
  hostname: string | null;
}
interface Detection {
  id: string;
  server_id: string;
  severity: EventSeverity;
  title: string;
  description: string | null;
  source_ip: string | null;
  status: string;
  detected_at: string;
}
interface QueuedAction {
  id: string;
  server_id: string;
  action_type: string;
  target_value: string;
  status: string;
  created_at: string;
}
interface BoardData {
  servers: FleetServer[];
  detections: Detection[];
  actions: QueuedAction[];
  map: AttackMapData | null;
}

const EMPTY: BoardData = { servers: [], detections: [], actions: [], map: null };
const SEVERITIES: Array<EventSeverity | 'all'> = ['all', 'critical', 'high', 'medium', 'low', 'info'];
const POLL_MS = 30_000;
const MAX_DETECTIONS = 200;
const ORG_REQUEST_CONCURRENCY = 4;

async function getJson<T>(path: string): Promise<T> {
  const response = await cloudFetch(path);
  const body = await response.json().catch(() => ({})) as Record<string, unknown>;
  if (!response.ok) {
    const message = typeof body.error === 'string' ? body.error : `Request failed (${response.status})`;
    throw new Error(response.status === 401 ? 'Your login expired. Run `threatcrush login` and try again.' : message);
  }
  return body as T;
}

async function loadBoard(): Promise<{ data: BoardData; warning: string }> {
  const [orgResult, fleetResult, mapResult] = await Promise.allSettled([
    getJson<{ organizations?: Organization[] }>('/api/orgs'),
    getJson<{ servers?: FleetServer[] }>('/api/fleet'),
    getJson<AttackMapData>('/api/attack-map?window=60'),
  ]);

  if (orgResult.status === 'rejected' || fleetResult.status === 'rejected') {
    const error = orgResult.status === 'rejected' ? orgResult.reason : (fleetResult as PromiseRejectedResult).reason;
    throw error instanceof Error ? error : new Error(String(error));
  }

  const servers = fleetResult.value.servers ?? [];
  const serverOrgIds = new Set(servers.map((server) => server.org_id));
  const organizations = (orgResult.value.organizations ?? []).filter((org) => serverOrgIds.has(org.id));
  const detailResults: Array<{
    detections: PromiseSettledResult<{ detections?: Detection[] }>;
    pendingActions: PromiseSettledResult<{ remediations?: QueuedAction[] }>;
    executingActions: PromiseSettledResult<{ remediations?: QueuedAction[] }>;
  }> = [];
  for (let offset = 0; offset < organizations.length; offset += ORG_REQUEST_CONCURRENCY) {
    const batch = organizations.slice(offset, offset + ORG_REQUEST_CONCURRENCY);
    detailResults.push(...await Promise.all(batch.map(async (org) => {
      const prefix = `/api/orgs/${encodeURIComponent(org.id)}`;
      const [detections, pendingActions, executingActions] = await Promise.allSettled([
        getJson<{ detections?: Detection[] }>(`${prefix}/detections?limit=${MAX_DETECTIONS}`),
        getJson<{ remediations?: QueuedAction[] }>(`${prefix}/remediations?limit=200&status=pending`),
        getJson<{ remediations?: QueuedAction[] }>(`${prefix}/remediations?limit=200&status=executing`),
      ]);
      return { detections, pendingActions, executingActions };
    })));
  }

  const detections: Detection[] = [];
  const actions: QueuedAction[] = [];
  let failedOrgs = 0;
  for (const result of detailResults) {
    if (result.detections.status === 'fulfilled') detections.push(...(result.detections.value.detections ?? []));
    if (result.pendingActions.status === 'fulfilled') actions.push(...(result.pendingActions.value.remediations ?? []));
    if (result.executingActions.status === 'fulfilled') actions.push(...(result.executingActions.value.remediations ?? []));
    if (result.detections.status === 'rejected' || result.pendingActions.status === 'rejected' || result.executingActions.status === 'rejected') failedOrgs++;
  }

  detections.sort((a, b) => Date.parse(b.detected_at) - Date.parse(a.detected_at));
  actions.sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  const warnings = [
    failedOrgs ? `Could not load detection or action data for ${failedOrgs} organization(s).` : '',
    mapResult.status === 'rejected' ? 'Attack map data is unavailable.' : '',
  ].filter(Boolean);
  return {
    data: {
      servers,
      detections,
      actions,
      map: mapResult.status === 'fulfilled' ? mapResult.value : null,
    },
    warning: warnings.join(' '),
  };
}

function recommendation(severity: EventSeverity): string {
  if (severity === 'critical') return 'Investigate host now';
  if (severity === 'high') return 'Verify source; block if unauthorized';
  if (severity === 'medium') return 'Check if expected, then resolve';
  return 'Review if unexpected';
}

function time(value: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'unknown';
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function connectionColor(connection: string): number {
  if (connection === 'online') return threatcrushTheme.success;
  if (connection === 'no-agent') return threatcrushTheme.muted;
  return severityColors.high;
}

function nextValue<T extends string>(values: T[], current: T, step = 1): T {
  const index = values.indexOf(current);
  return values[(Math.max(0, index) + step + values.length) % values.length] ?? values[0] ?? current;
}

export async function startActionCenter(): Promise<void> {
  const app = await createApp({
    theme: threatcrushTheme,
    title: 'ThreatCrush — Action Center',
    mouse: true,
    fps: 20,
    quitKeys: [],
  });
  const geo = new GeoResolver(() => app.invalidate());
  const mapState = initialState();
  let data = EMPTY;
  let severity: EventSeverity | 'all' = 'all';
  let fleetId = 'all';
  let serverId = 'all';
  let ipFilter = '';
  let editingIp = false;
  let selected = 0;
  let loading = true;
  let error = '';
  let warning = '';
  let stopped = false;
  let refreshing = false;
  let showMap = false;

  const refresh = async (): Promise<void> => {
    if (refreshing || stopped) return;
    refreshing = true;
    try {
      const result = await loadBoard();
      data = result.data;
      warning = result.warning;
      error = '';
      loading = false;
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
      loading = false;
    } finally {
      refreshing = false;
      app.invalidate();
    }
  };

  const interval = setInterval(() => { void refresh(); }, POLL_MS);
  interval.unref?.();
  void refresh();

  const serverById = (): Map<string, FleetServer> => new Map(data.servers.map((server) => [server.id, server]));
  const fleets = (): Array<{ id: string; label: string }> => {
    const seen = new Map<string, string>();
    for (const server of data.servers) {
      if (server.fleet_id) seen.set(server.fleet_id, `${server.org_slug} / ${server.fleet_name ?? 'Fleet'}`);
    }
    return [...seen].map(([id, label]) => ({ id, label })).sort((a, b) => a.label.localeCompare(b.label));
  };
  const servers = (): FleetServer[] => data.servers
    .filter((server) => fleetId === 'all' || server.fleet_id === fleetId)
    .sort((a, b) => `${a.org_slug}/${a.name}`.localeCompare(`${b.org_slug}/${b.name}`));
  const filtered = (): Detection[] => {
    const byId = serverById();
    const ip = ipFilter.trim().toLowerCase();
    return data.detections.filter((detection) => {
      const server = byId.get(detection.server_id);
      return (severity === 'all' || detection.severity === severity)
        && (fleetId === 'all' || server?.fleet_id === fleetId)
        && (serverId === 'all' || detection.server_id === serverId)
        && (!ip || detection.source_ip?.toLowerCase().includes(ip));
    });
  };

  const quit = (): void => {
    stopped = true;
    clearInterval(interval);
    geo.stop();
    app.stop();
  };

  app.on('key', (event) => {
    if (editingIp) {
      if (event.key === 'escape') editingIp = false;
      else if (event.key === 'enter' || event.key === 'return') editingIp = false;
      else if (event.key === 'backspace') ipFilter = ipFilter.slice(0, -1);
      else if (event.key === 'ctrl+u') ipFilter = '';
      else if (event.char && event.char >= ' ' && ipFilter.length < 80) ipFilter += event.char;
      app.invalidate();
      return;
    }
    switch (event.key) {
      case 'q':
      case 'ctrl+c':
        quit();
        break;
      case 'r':
        void refresh();
        break;
      case 'm':
        showMap = !showMap;
        break;
      case '/':
        editingIp = true;
        break;
      case 'escape':
        if (ipFilter) ipFilter = '';
        else if (serverId !== 'all') serverId = 'all';
        else if (fleetId !== 'all') { fleetId = 'all'; serverId = 'all'; }
        else severity = 'all';
        break;
      case 's':
        severity = nextValue(SEVERITIES, severity);
        selected = 0;
        break;
      case 'f': {
        const values = ['all', ...fleets().map((item) => item.id)];
        fleetId = nextValue(values, fleetId);
        serverId = 'all';
        selected = 0;
        break;
      }
      case 'h': {
        const values = ['all', ...servers().map((server) => server.id)];
        serverId = nextValue(values, serverId);
        selected = 0;
        break;
      }
      case 'up':
      case 'k':
        selected = Math.max(0, selected - 1);
        break;
      case 'down':
      case 'j':
        selected = Math.min(Math.max(0, filtered().length - 1), selected + 1);
        break;
      case 'home':
        selected = 0;
        break;
      case 'end':
        selected = Math.max(0, filtered().length - 1);
        break;
      default:
        break;
    }
    app.invalidate();
  });

  app.on('paste', (event) => {
    if (!editingIp) return;
    ipFilter = `${ipFilter}${event.text.replace(/[\r\n]/g, '').slice(0, 80 - ipFilter.length)}`;
    app.invalidate();
  });

  app.render(({ ui, theme }) => {
    if (showMap && data.map) {
      mapBody(ui, mapState, theme, { data: data.map, geo });
      ui.statusBar({ size: 1, items: [{ key: 'm', label: 'events' }, { key: 'r', label: 'refresh' }, { key: 'q', label: 'quit' }] });
      return;
    }

    ui.box({ size: 3, border: 'rounded', borderColor: theme.border, padding: [0, 1] }, (box) => {
      box.row({ size: 1 }, (row) => {
        row.text('⚡ THREATCRUSH · ACTION CENTER', { fg: theme.primary, bold: true, size: 35 });
        row.text(loading ? 'LOADING' : error ? 'OFFLINE' : 'LIVE', {
          fg: error ? severityColors.high : loading ? theme.warning : theme.success,
          bold: true,
          size: 8,
        });
        row.text(error || warning || 'Fleet detections, server health, and queued actions', { fg: error ? severityColors.high : theme.muted, size: 'fill' });
      });
    });

    const list = filtered();
    selected = Math.min(selected, Math.max(0, list.length - 1));
    const selectedDetection = list[selected];
    const serverMap = serverById();
    const online = data.servers.filter((server) => server.connection === 'online').length;
    const pending = data.actions.length;

    ui.row({ size: 4, gap: 1 }, (row) => {
      summary(row, theme, 'SERVERS ONLINE', `${online}/${data.servers.length}`, theme.success);
      summary(row, theme, 'DETECTIONS', String(data.detections.length), severityColors.high);
      summary(row, theme, 'QUEUED ACTIONS', String(pending), theme.warning);
      summary(row, theme, 'FILTERED EVENTS', String(list.length), theme.accent);
    });

    ui.row({ size: 1 }, (row) => {
      const selectedHost = serverMap.get(serverId);
      row.text(`severity ${severity}  ·  fleet ${fleetId === 'all' ? 'all' : fleets().find((x) => x.id === fleetId)?.label ?? 'unknown'}  ·  host ${selectedHost ? `${selectedHost.org_slug}/${selectedHost.name}` : 'all'}`, { fg: theme.foreground, size: 'fill' });
      row.text(`source IP ${editingIp ? `/${ipFilter}▏` : ipFilter || 'all'}`, { fg: editingIp ? theme.primary : theme.muted, size: 24 });
    });

    ui.row({ size: 'fill', gap: 1 }, (row) => {
      row.column({ size: '2fr' }, (left) => {
        left.panel({ title: 'LATEST DETECTIONS · RECOMMENDED ACTION', size: 'fill', border: 'rounded', borderColor: theme.border, titleColor: theme.primary, padding: [0, 1] }, (panel) => {
          if (loading) { panel.label('Loading detections…', { fg: theme.muted }); return; }
          if (list.length === 0) { panel.label(error ? 'Sign in and refresh to load fleet activity.' : 'No detections match these filters.', { fg: theme.muted }); return; }
          panel.table({
            rows: list,
            header: true,
            selected,
            followSelection: true,
            scrollbar: true,
            columns: [
              { key: 'severity', width: 9, render: (d) => d.severity.toUpperCase(), color: (d) => severityColors[d.severity] },
              { key: 'server_id', width: 20, render: (d) => serverMap.get(d.server_id)?.name ?? 'unknown host', color: () => theme.foreground },
              { key: 'source_ip', width: 16, render: (d) => d.source_ip ?? '—', color: () => theme.muted },
              { key: 'title', width: 'fill', color: () => theme.foreground },
              { key: 'severity', width: 31, title: 'NEXT STEP', render: (d) => recommendation(d.severity), color: (d) => severityColors[d.severity] },
            ],
          });
        });
      });

      row.column({ size: '1fr' }, (right) => {
        right.panel({ title: 'SERVERS', size: '2fr', border: 'rounded', borderColor: theme.border, titleColor: theme.primary, padding: [0, 1] }, (panel) => {
          if (data.servers.length === 0) { panel.label('No linked servers.', { fg: theme.muted }); return; }
          panel.table({
            rows: servers(),
            header: true,
            columns: [
              { key: 'connection', width: 9, render: (server) => server.connection, color: (server) => connectionColor(server.connection) },
              { key: 'name', width: 'fill', render: (server) => `${server.org_slug} / ${server.name}`, color: () => theme.foreground },
            ],
          });
        });

        right.panel({ title: 'QUEUED ACTIONS', size: '1fr', border: 'rounded', borderColor: theme.border, titleColor: theme.primary, padding: [0, 1] }, (panel) => {
          if (pending === 0) { panel.label('No pending actions.', { fg: theme.muted }); return; }
          for (const action of data.actions.slice(0, 8)) {
            const host = serverMap.get(action.server_id)?.name ?? 'unknown host';
            panel.row({ size: 1 }, (line) => {
              line.text(`${action.action_type} ${action.target_value}`, { fg: theme.foreground, size: 'fill' });
              line.text(action.status, { fg: theme.warning, size: 12, align: 'right' });
            });
            panel.label(`${host} · ${time(action.created_at)}`, { fg: theme.muted, size: 1 });
          }
        });

        if (selectedDetection) {
          right.panel({ title: 'SELECTED EVENT', size: 1, border: 'rounded', borderColor: theme.border, titleColor: theme.primary, padding: [0, 1] }, (panel) => {
            const host = serverMap.get(selectedDetection.server_id);
            panel.text(`${selectedDetection.title} · ${recommendation(selectedDetection.severity)}`, { fg: severityColors[selectedDetection.severity] });
            panel.label(`${host?.org_slug ?? 'org'} / ${host?.name ?? 'unknown host'} · ${time(selectedDetection.detected_at)} · ${selectedDetection.status}`, { fg: theme.muted, size: 1 });
            if (selectedDetection.description) panel.label(selectedDetection.description, { fg: theme.foreground, size: 2 });
          });
        }
      });
    });

    ui.statusBar({
      size: 1,
      items: editingIp
        ? [{ key: 'enter', label: 'apply IP filter' }, { key: 'esc', label: 'cancel' }, { key: 'ctrl+u', label: 'clear' }]
        : [{ key: 'q', label: 'quit' }, { key: 'r', label: 'refresh' }, { key: 'm', label: 'attack map' }, { key: 's', label: 'severity' }, { key: 'f', label: 'fleet' }, { key: 'h', label: 'host' }, { key: '/', label: 'source IP' }, { key: '↑↓', label: 'select' }, { key: 'esc', label: 'clear filters' }],
    });
  });

  try {
    await app.start();
  } finally {
    stopped = true;
    clearInterval(interval);
    geo.stop();
  }
}

function summary(parent: import('@profullstack/hqtui').Container, theme: import('@profullstack/hqtui').Theme, label: string, value: string, color: number): void {
  parent.panel({ title: label, size: 'fill', border: 'rounded', borderColor: theme.border, titleColor: theme.muted, padding: [0, 1] }, (panel) => {
    panel.text(value, { fg: color, bold: true, size: 18 });
  });
}
