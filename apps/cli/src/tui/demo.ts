import type { ThreatEvent } from '../types/events.js';

/**
 * Canned traffic for `--demo`. This exists for screenshots and for showing the
 * dashboard on a host with no daemon; it is never reached unless the flag is
 * passed, so an unattended TUI can no longer pass fiction off as telemetry.
 */
const SCRIPT: Array<Omit<ThreatEvent, 'timestamp'>> = [
  { module: 'network-monitor', category: 'network', severity: 'info', message: 'Monitoring 847 connections', source_ip: undefined },
  { module: 'log-watcher', category: 'web', severity: 'medium', message: 'SQLi attempt — :443 /api/users?id=1 OR 1=1', source_ip: '185.43.21.8' },
  { module: 'ssh-guard', category: 'auth', severity: 'high', message: 'SSH brute force — :22 47 failed attempts', source_ip: '91.232.105.3' },
  { module: 'network-monitor', category: 'network', severity: 'medium', message: 'Port scan — :21-:8080 (SYN flood)', source_ip: '45.33.32.156' },
  { module: 'dns-monitor', category: 'network', severity: 'medium', message: 'DNS tunneling — :53 suspicious TXT queries', source_ip: '103.44.8.2' },
  { module: 'firewall-rules', category: 'network', severity: 'info', message: 'Tar pit engaged — slowing attacker', source_ip: '91.232.105.3' },
  { module: 'log-watcher', category: 'web', severity: 'critical', message: 'XSS attempt — :443 /search?q=<script>', source_ip: '77.88.55.60' },
  { module: 'firewall-rules', category: 'network', severity: 'info', message: 'Rate limited (50 req/s)', source_ip: '45.33.32.156' },
  { module: 'ssh-guard', category: 'auth', severity: 'low', message: 'SSH login accepted for deploy', source_ip: '10.0.0.14' },
  { module: 'log-watcher', category: 'web', severity: 'high', message: 'Path traversal — GET /../../etc/passwd', source_ip: '185.43.21.8' },
];

export function demoEvent(index: number): ThreatEvent {
  const base = SCRIPT[index % SCRIPT.length]!;
  return { ...base, timestamp: new Date() };
}

export const demoScriptLength = SCRIPT.length;
