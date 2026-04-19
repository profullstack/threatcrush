import type { Severity } from '../config';
import { severityColors } from '../config';

/** Format a timestamp to relative time (e.g. "2m ago") */
export function timeAgo(timestamp: string): string {
  const now = Date.now();
  const then = new Date(timestamp).getTime();
  const diff = Math.floor((now - then) / 1000);

  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

/** Get color for a severity level */
export function getSeverityColor(severity: Severity): string {
  return severityColors[severity] || '#666666';
}

/** Format large numbers (e.g. 1234 → "1.2k") */
export function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toString();
}

/** Format uptime hours to human readable */
export function formatUptime(hours: number): string {
  if (hours < 1) return `${Math.floor(hours * 60)}m`;
  if (hours < 24) return `${Math.floor(hours)}h`;
  const days = Math.floor(hours / 24);
  const h = Math.floor(hours % 24);
  return `${days}d ${h}h`;
}
