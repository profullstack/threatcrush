import blessed from 'blessed';
import contrib from 'blessed-contrib';
import {
  getRecentEvents,
  getEventCount,
  getThreatCount,
  getTopSources,
  initStateDB,
  insertEvent,
  closeDB,
} from '../core/state.js';
import { formatEvent } from '../core/logger.js';
import type { ThreatEvent, EventSeverity } from '../types/events.js';

interface DemoEvent {
  module: string;
  category: string;
  severity: EventSeverity;
  message: string;
  source_ip?: string;
}

const DEMO_EVENTS: DemoEvent[] = [
  { module: 'ssh-guard', category: 'auth', severity: 'info', message: 'SSH login accepted for ubuntu', source_ip: '10.0.0.1' },
  { module: 'log-watcher', category: 'web', severity: 'info', message: 'GET /api/health → 200', source_ip: '172.16.0.50' },
  { module: 'ssh-guard', category: 'auth', severity: 'high', message: 'Failed SSH login for root', source_ip: '45.33.22.11' },
  { module: 'log-watcher', category: 'web', severity: 'low', message: 'GET /admin → 404', source_ip: '91.121.44.55' },
  { module: 'ssh-guard', category: 'auth', severity: 'high', message: 'Failed SSH login for admin', source_ip: '45.33.22.11' },
  { module: 'log-watcher', category: 'web', severity: 'critical', message: 'Attack [SQLI]: GET /search?q=1%27+OR+1%3D1', source_ip: '185.220.101.44' },
  { module: 'log-watcher', category: 'web', severity: 'medium', message: 'Server error 502: GET /api/users', source_ip: '10.0.0.2' },
  { module: 'ssh-guard', category: 'auth', severity: 'high', message: 'Invalid SSH user: admin123', source_ip: '103.77.88.99' },
  { module: 'log-watcher', category: 'web', severity: 'critical', message: 'Attack [PATH_TRAVERSAL]: GET /../../etc/passwd', source_ip: '185.220.101.44' },
  { module: 'ssh-guard', category: 'auth', severity: 'high', message: 'Brute force — 6 failures in 45s', source_ip: '45.33.22.11' },
  { module: 'log-watcher', category: 'system', severity: 'medium', message: 'Outbound connection to 198.51.100.1:4444', source_ip: '198.51.100.1' },
  { module: 'log-watcher', category: 'web', severity: 'info', message: 'GET /index.html → 200', source_ip: '172.16.0.51' },
  { module: 'ssh-guard', category: 'auth', severity: 'high', message: 'Failed SSH login for deploy', source_ip: '194.26.192.64' },
  { module: 'log-watcher', category: 'web', severity: 'critical', message: 'Attack [XSS]: GET /comment?body=<script>alert(1)</script>', source_ip: '185.220.101.44' },
  { module: 'log-watcher', category: 'web', severity: 'low', message: 'GET /robots.txt → 200', source_ip: '66.249.66.1' },
  { module: 'ssh-guard', category: 'auth', severity: 'high', message: 'Failed SSH login for test', source_ip: '45.33.22.11' },
  { module: 'log-watcher', category: 'network', severity: 'medium', message: 'Port scan detected from 103.77.88.99', source_ip: '103.77.88.99' },
  { module: 'ssh-guard', category: 'auth', severity: 'high', message: 'Failed SSH login for root', source_ip: '194.26.192.64' },
];

let demoIndex = 0;

function severityColorBlessed(severity: EventSeverity): string {
  const colors: Record<EventSeverity, string> = {
    info: 'green',
    low: 'cyan',
    medium: 'yellow',
    high: 'red',
    critical: 'magenta',
  };
  return colors[severity] || 'white';
}

function formatTimestamp(date: Date = new Date()): string {
  return date.toISOString().slice(0, 19).replace('T', ' ');
}

function eventLine(event: ThreatEvent): string {
  const ts = formatTimestamp(event.timestamp);
  const sev = `[${event.severity.toUpperCase()}]`.padEnd(10);
  const mod = `[${event.module}]`.padEnd(14);
  const ip = event.source_ip ? ` (${event.source_ip})` : '';
  return `{${severityColorBlessed(event.severity)}-bold}${ts}{/${severityColorBlessed(event.severity)}-bold} {cyan}${mod}{/cyan} {${severityColorBlessed(event.severity)}}${sev}{/${severityColorBlessed(event.severity)}} ${event.message}${ip}`;
}

export async function startDashboard(): Promise<void> {
  initStateDB();

  const screen = blessed.screen({
    smartCSR: true,
    fullUnicode: true,
    title: 'ThreatCrush TUI Dashboard',
  });

  // ── Layout ──

  const grid = new contrib.grid({ rows: 12, cols: 12, screen });

  // Title bar
  const titleBox = grid.set(0, 0, 1, 12, blessed.box, {
    content: '  ⚡ ThreatCrush  —  Interactive Security Dashboard',
    tags: true,
    style: {
      fg: 'green',
      border: { fg: 'green' },
    },
    border: { type: 'line' },
  });

  // Stats boxes (top row)
  const totalBox = grid.set(1, 0, 2, 3, blessed.box, {
    label: ' Total Events ',
    tags: true,
    content: '{green-fg}0{/green-fg}',
    style: { border: { fg: 'green' } },
    border: { type: 'line' },
  });

  const threatBox = grid.set(1, 3, 2, 3, blessed.box, {
    label: ' Threats ',
    tags: true,
    content: '{red-fg}0{/red-fg}',
    style: { border: { fg: 'red' } },
    border: { type: 'line' },
  });

  const moduleBox = grid.set(1, 6, 2, 3, blessed.box, {
    label: ' Active Modules ',
    tags: true,
    content: '{cyan-fg}0{/cyan-fg}',
    style: { border: { fg: 'cyan' } },
    border: { type: 'line' },
  });

  const statusBox = grid.set(1, 9, 2, 3, blessed.box, {
    label: ' Status ',
    tags: true,
    content: '{green-fg}● MONITORING{/green-fg}',
    style: { border: { fg: 'green' } },
    border: { type: 'line' },
  });

  // Severity donut chart
  const donut = grid.set(3, 0, 4, 4, contrib.donut, {
    label: ' Severity Breakdown ',
    radius: 8,
    arcWidth: 3,
    remainColor: 'black',
    data: [
      { percent: 0, label: 'Info', color: 'green' },
      { percent: 0, label: 'Low', color: 'cyan' },
      { percent: 0, label: 'Medium', color: 'yellow' },
      { percent: 0, label: 'High', color: 'red' },
      { percent: 0, label: 'Critical', color: 'magenta' },
    ],
  });

  // Top sources spark/bar chart
  const topSourcesTable = grid.set(3, 4, 4, 4, contrib.table, {
    label: ' Top Threat Sources ',
    keys: true,
    interactive: false,
    columnSpacing: 2,
    columnWidth: [18, 8],
    style: { border: { fg: 'yellow' } },
    border: { type: 'line' },
  });

  // Events over time sparkline
  const sparkline = grid.set(3, 8, 4, 4, contrib.sparkline, {
    label: ' Events Over Time ',
    tags: true,
    style: { border: { fg: 'blue' } },
    border: { type: 'line' },
    sparkline: { fill: true },
  });

  // Live event feed (scrollable log)
  const eventLog = grid.set(7, 0, 5, 8, contrib.log, {
    label: ' Live Event Feed ',
    tags: true,
    keys: true,
    interactive: false,
    style: { border: { fg: 'green' } },
    border: { type: 'line' },
  });

  // Module status
  const moduleStatus = grid.set(7, 8, 5, 4, contrib.table, {
    label: ' Module Status ',
    keys: true,
    interactive: false,
    columnSpacing: 2,
    columnWidth: [16, 10],
    style: { border: { fg: 'cyan' } },
    border: { type: 'line' },
  });

  // Bottom status bar
  const statusBar = grid.set(11, 0, 1, 12, blessed.box, {
    tags: true,
    content: ' {green-fg}q{/green-fg}:exit  {green-fg}r{/green-fg}:reset  {green-fg}p{/green-fg}:pause  |  {green-fg}↑↓{/green-fg}:scroll feed',
    style: { border: { fg: 'green' } },
    border: { type: 'line' },
  });

  // ── State ──

  let paused = false;
  let eventsHistory: ThreatEvent[] = [];
  let eventTimeline: number[] = []; // events per tick
  let tickCount = 0;
  const activeModules = new Set<string>();
  const modules: Record<string, { status: string; events: number }> = {};

  function updateStats() {
    const total = getEventCount();
    const threats = getThreatCount();

    totalBox.setContent(`{green-fg}${total}{/green-fg}`);
    threatBox.setContent(`{red-fg}${threats}{/red-fg}`);
    moduleBox.setContent(`{cyan-fg}${activeModules.size}{/cyan-fg}`);

    // Severity donut
    const bySeverity: Record<EventSeverity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    const recent = getRecentEvents(200);
    for (const e of recent) {
      bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1;
    }
    const totalRecent = recent.length || 1;
    donut.setData([
      { percent: Math.round((bySeverity.info / totalRecent) * 100), label: `Info ${bySeverity.info}`, color: 'green' },
      { percent: Math.round((bySeverity.low / totalRecent) * 100), label: `Low ${bySeverity.low}`, color: 'cyan' },
      { percent: Math.round((bySeverity.medium / totalRecent) * 100), label: `Med ${bySeverity.medium}`, color: 'yellow' },
      { percent: Math.round((bySeverity.high / totalRecent) * 100), label: `High ${bySeverity.high}`, color: 'red' },
      { percent: Math.round((bySeverity.critical / totalRecent) * 100), label: `Crit ${bySeverity.critical}`, color: 'magenta' },
    ]);

    // Top sources
    const sources = getTopSources(8);
    topSourcesTable.setData({
      headers: ['IP Address', 'Count'],
      data: sources.map((s: { ip: string; count: number }) => [s.ip, String(s.count)]),
    });

    // Sparkline
    tickCount++;
    eventTimeline.push(eventsHistory.length);
    if (eventTimeline.length > 30) eventTimeline.shift();
    sparkline.setData(
      ['Events'],
      [eventTimeline],
    );

    // Module status
    const modData = Object.entries(modules).map(([name, info]) => [name, `${info.events} events`]);
    if (modData.length === 0) modData.push(['log-watcher', 'monitoring'], ['ssh-guard', 'monitoring']);
    moduleStatus.setData({
      headers: ['Module', 'Activity'],
      data: modData,
    });

    screen.render();
  }

  function addEvent(event: ThreatEvent) {
    if (paused) return;

    eventsHistory.push(event);
    activeModules.add(event.module);

    if (!modules[event.module]) {
      modules[event.module] = { status: 'active', events: 0 };
    }
    modules[event.module].events++;

    try {
      insertEvent(event);
    } catch {
      // DB may be unavailable
    }

    eventLog.log(eventLine(event));

    // Keep log manageable
    if (eventLog.children.length > 500) {
      eventLog.emit('set content', '');
    }

    updateStats();
  }

  function injectDemoEvent() {
    const demo = DEMO_EVENTS[demoIndex % DEMO_EVENTS.length];
    demoIndex++;
    addEvent({
      timestamp: new Date(),
      module: demo.module,
      category: demo.category as ThreatEvent['category'],
      severity: demo.severity,
      message: demo.message,
      source_ip: demo.source_ip,
    });
  }

  // ── Key bindings ──

  screen.key('q', () => {
    closeDB();
    process.exit(0);
  });

  screen.key('p', () => {
    paused = !paused;
    statusBox.setContent(paused
      ? '{yellow-fg}● PAUSED{/yellow-fg}'
      : '{green-fg}● MONITORING{/green-fg}'
    );
    screen.render();
  });

  screen.key('r', () => {
    eventsHistory = [];
    eventTimeline = [];
    tickCount = 0;
    activeModules.clear();
    for (const mod of Object.keys(modules)) {
      modules[mod].events = 0;
    }
    eventLog.setContent('');
    updateStats();
  });

  screen.key(['escape', 'q', 'C-c'], () => {
    closeDB();
    process.exit(0);
  });

  screen.render();
  updateStats();

  // Inject demo events at intervals
  const demoInterval = setInterval(() => {
    injectDemoEvent();
  }, 2000);

  // Update stats periodically
  const statsInterval = setInterval(() => {
    updateStats();
  }, 3000);

  // Cleanup on exit
  process.on('SIGINT', () => {
    clearInterval(demoInterval);
    clearInterval(statsInterval);
    closeDB();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    clearInterval(demoInterval);
    clearInterval(statsInterval);
    closeDB();
    process.exit(0);
  });
}
