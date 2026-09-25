import { theme } from '../config';
import type { Severity } from './api';

/** Relative time, e.g. "2m ago". Future and invalid timestamps read "just now". */
export function timeAgo(timestamp: string | null, now = Date.now()): string {
  if (!timestamp) return 'never';
  const diff = Math.floor((now - new Date(timestamp).getTime()) / 1000);
  if (!Number.isFinite(diff) || diff < 5) return 'just now';
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  info: theme.blue,
  low: theme.dim,
  medium: theme.yellow,
  high: theme.orange,
  critical: theme.red,
};
