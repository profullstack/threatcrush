import { existsSync, createReadStream, statSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { watch } from 'node:fs';
import chalk from 'chalk';
import { formatEvent, logger, banner } from '../core/logger.js';
import { autoDetectParser, detectAttackPattern, parseAuthLog, parseNginxLog } from '../core/log-parser.js';
import { initStateDB, insertEvent } from '../core/state.js';
import type { ThreatEvent, EventSeverity, EventCategory } from '../types/events.js';

interface MonitorOptions {
  module?: string;
  tui?: boolean;
}

interface LogWatcher {
  path: string;
  name: string;
  category: EventCategory;
}

const LOG_SOURCES: LogWatcher[] = [
  { path: '/var/log/auth.log', name: 'ssh-guard', category: 'auth' },
  { path: '/var/log/secure', name: 'ssh-guard', category: 'auth' },
  { path: '/var/log/nginx/access.log', name: 'log-watcher', category: 'web' },
  { path: '/var/log/syslog', name: 'log-watcher', category: 'system' },
];

export async function monitorCommand(options: MonitorOptions): Promise<void> {
  if (options.tui) {
    // Dynamic import to avoid loading blessed when not needed
    const { startDashboard } = await import('../tui/dashboard.js');
    await startDashboard();
    return;
  }

  banner();
  logger.info('Starting foreground monitor...');

  const moduleFilter = options.module?.split(',').map((m) => m.trim());

  // Find available log files
  const availableSources = LOG_SOURCES.filter((s) => {
    if (moduleFilter && !moduleFilter.includes(s.name)) return false;
    return existsSync(s.path);
  });

  if (availableSources.length === 0) {
    logger.warn('No log files found to monitor.');
    logger.info('Available log paths checked:');
    for (const s of LOG_SOURCES) {
      const exists = existsSync(s.path);
      console.log(`  ${exists ? chalk.green('✓') : chalk.red('✗')} ${s.path}`);
    }
    console.log();
    logger.info('Starting demo mode with synthetic events...\n');
    await runDemoMode();
    return;
  }

  try {
    initStateDB();
  } catch {
    // State DB optional for monitoring
  }

  logger.info(`Monitoring ${availableSources.length} log source(s):`);
  for (const src of availableSources) {
    console.log(`  ${chalk.green('●')} ${chalk.white(src.name.padEnd(14))} → ${chalk.gray(src.path)}`);
  }
  console.log();
  console.log(chalk.gray('  Press Ctrl+C to stop\n'));

  // Tail each log file
  for (const src of availableSources) {
    tailLog(src);
  }

  // Keep process alive
  await new Promise(() => {});
}

function tailLog(source: LogWatcher): void {
  const { path, name, category } = source;

  // Start reading from end of file
  const stat = statSync(path);
  let position = stat.size;

  const checkForNewData = () => {
    try {
      const currentStat = statSync(path);
      if (currentStat.size <= position) {
        if (currentStat.size < position) position = 0; // file rotated
        return;
      }

      const stream = createReadStream(path, { start: position, encoding: 'utf-8' });
      const rl = createInterface({ input: stream });

      rl.on('line', (line) => {
        if (!line.trim()) return;
        processLine(line, name, category);
      });

      rl.on('close', () => {
        position = currentStat.size;
      });
    } catch {
      // file may not be readable
    }
  };

  // Poll for changes (more reliable than fs.watch for log files)
  setInterval(checkForNewData, 1000);
}

function processLine(line: string, moduleName: string, category: EventCategory): void {
  const parsed = autoDetectParser(line);
  if (!parsed) return;

  let severity: EventSeverity = 'info';
  let message = line;

  if (parsed.source === 'auth') {
    const authEntry = parseAuthLog(line);
    if (!authEntry) return;

    if (/failed password/i.test(authEntry.fields.message)) {
      severity = 'high';
      message = `Failed SSH login for ${authEntry.fields.user || 'unknown'} from ${authEntry.fields.ip || 'unknown'}`;
    } else if (/accepted/i.test(authEntry.fields.message)) {
      severity = 'info';
      message = `SSH login accepted for ${authEntry.fields.user || 'unknown'}`;
    } else if (/invalid user/i.test(authEntry.fields.message)) {
      severity = 'high';
      message = `Invalid SSH user attempt: ${authEntry.fields.user || 'unknown'} from ${authEntry.fields.ip || 'unknown'}`;
    }
  } else if (parsed.source === 'nginx') {
    const nginxEntry = parseNginxLog(line);
    if (!nginxEntry) return;

    const status = parseInt(nginxEntry.fields.status);
    const attack = detectAttackPattern(nginxEntry.fields.path);

    if (attack) {
      severity = 'critical';
      message = `Attack detected [${attack.toUpperCase()}]: ${nginxEntry.fields.method} ${nginxEntry.fields.path}`;
    } else if (status >= 500) {
      severity = 'medium';
      message = `Server error ${status}: ${nginxEntry.fields.method} ${nginxEntry.fields.path}`;
    } else if (status >= 400) {
      severity = 'low';
      message = `Client error ${status}: ${nginxEntry.fields.method} ${nginxEntry.fields.path}`;
    } else {
      severity = 'info';
      message = `${nginxEntry.fields.method} ${nginxEntry.fields.path} → ${status}`;
    }
  }

  const event: ThreatEvent = {
    timestamp: new Date(),
    module: moduleName,
    category,
    severity,
    message,
    source_ip: parsed.fields.ip as string | undefined,
  };

  console.log(formatEvent(event.module, event.severity, event.message, event.source_ip));

  try {
    insertEvent(event);
  } catch {
    // State DB may not be available
  }
}

async function runDemoMode(): Promise<void> {
  const demoEvents: Array<Omit<ThreatEvent, 'timestamp'>> = [
    { module: 'ssh-guard', category: 'auth', severity: 'info', message: 'SSH login accepted for ubuntu', source_ip: '10.0.0.1' },
    { module: 'log-watcher', category: 'web', severity: 'info', message: 'GET /api/health → 200', source_ip: '172.16.0.50' },
    { module: 'ssh-guard', category: 'auth', severity: 'high', message: 'Failed SSH login for root', source_ip: '45.33.22.11' },
    { module: 'log-watcher', category: 'web', severity: 'low', message: 'GET /admin → 404', source_ip: '91.121.44.55' },
    { module: 'ssh-guard', category: 'auth', severity: 'high', message: 'Failed SSH login for admin', source_ip: '45.33.22.11' },
    { module: 'log-watcher', category: 'web', severity: 'critical', message: 'Attack detected [SQLI]: GET /search?q=1%27+OR+1%3D1', source_ip: '185.220.101.44' },
    { module: 'log-watcher', category: 'web', severity: 'medium', message: 'Server error 502: GET /api/users', source_ip: '10.0.0.2' },
    { module: 'ssh-guard', category: 'auth', severity: 'high', message: 'Invalid SSH user attempt: admin123', source_ip: '103.77.88.99' },
    { module: 'log-watcher', category: 'web', severity: 'critical', message: 'Attack detected [PATH_TRAVERSAL]: GET /../../etc/passwd', source_ip: '185.220.101.44' },
    { module: 'ssh-guard', category: 'auth', severity: 'high', message: 'Brute force detected — 6 failures in 45s', source_ip: '45.33.22.11' },
    { module: 'log-watcher', category: 'system', severity: 'medium', message: 'Unusual outbound connection to 198.51.100.1:4444', source_ip: '198.51.100.1' },
    { module: 'log-watcher', category: 'web', severity: 'info', message: 'GET /index.html → 200', source_ip: '172.16.0.51' },
  ];

  let i = 0;
  const interval = setInterval(() => {
    const event = demoEvents[i % demoEvents.length];
    console.log(formatEvent(event.module, event.severity, event.message, event.source_ip));
    i++;
  }, 1500 + Math.random() * 2000);

  process.on('SIGINT', () => {
    clearInterval(interval);
    console.log(chalk.gray('\n  Monitor stopped.'));
    process.exit(0);
  });

  await new Promise(() => {});
}
