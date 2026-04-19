import os from 'node:os';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface StructuredFinding {
  type: string;
  severity: Severity;
  message: string;
  location?: string;
  details?: Record<string, unknown>;
}

export interface RunResult {
  type: 'scan' | 'pentest';
  target: string;
  findings: StructuredFinding[];
  severity_summary: Record<Severity, number>;
  summary: string;
  error?: string;
}

export function emptyCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function summarize(findings: StructuredFinding[]): Record<Severity, number> {
  const counts = emptyCounts();
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return counts;
}

export function workerId(): string {
  return `${os.hostname()}/${process.pid}`;
}
