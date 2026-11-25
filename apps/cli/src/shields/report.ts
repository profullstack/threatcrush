/**
 * Turn a Shields scan into the standard RunResult the rest of ThreatCrush
 * consumes, and render the classic three-state port grid for the terminal.
 */

import { HIGH_RISK_OPEN } from './ports.js';
import { summarizeShields, type PortResult, type ShieldsSummary } from './scan.js';
import type { RunResult, Severity, StructuredFinding } from '../core/run-result.js';
import { summarize } from '../core/run-result.js';

export interface ShieldsReport {
  summary: ShieldsSummary;
  result: RunResult;
  /** Every probed port and its state, in scan order (for grid rendering). */
  results: PortResult[];
}

/** Severity for a single open port: high for the dangerous services, else medium. */
function openSeverity(port: number): Severity {
  return HIGH_RISK_OPEN.has(port) ? 'high' : 'medium';
}

export function buildShieldsReport(target: string, results: PortResult[]): ShieldsReport {
  const summary = summarizeShields(results, HIGH_RISK_OPEN);
  const findings: StructuredFinding[] = [];

  for (const r of summary.openPorts) {
    findings.push({
      type: 'open-port',
      severity: openSeverity(r.port),
      message: `TCP ${r.port}${r.name ? ` (${r.name})` : ''} is OPEN — reachable from the Internet`,
      location: `${target}:${r.port}`,
      details: {
        port: r.port,
        service: r.name || undefined,
        remediation: HIGH_RISK_OPEN.has(r.port)
          ? 'Firewall this port or stop the service. Exposing it to the Internet is high-risk.'
          : 'Confirm this port is meant to be public; otherwise firewall it.',
      },
    });
  }

  // A machine that answers "closed" is visible (not stealth). Report it once,
  // informationally, the way the classic test flags a non-stealth result.
  if (summary.open === 0 && summary.closed > 0) {
    findings.push({
      type: 'not-stealth',
      severity: 'low',
      message: `${summary.closed} port(s) replied "closed" instead of staying silent — your machine is visible to the Internet`,
      location: target,
      details: {
        closed: summary.closed,
        remediation: 'For full stealth, configure your firewall to DROP (not REJECT) unsolicited packets.',
      },
    });
  }

  const counts = summarize(findings);
  const result: RunResult = {
    type: 'shields',
    target,
    findings,
    severity_summary: counts,
    summary: `${summary.open} open · ${summary.closed} closed · ${summary.stealth} stealth of ${summary.total} — ${summary.verdict}`,
  };
  return { summary, result, results };
}

const STATE_GLYPH = {
  open: '●',
  closed: '○',
  stealth: '·',
} as const;

/**
 * Render the classic port grid as plain text with per-state glyphs. `color`
 * lets the CLI inject chalk; the web uses its own renderer.
 */
export function renderGrid(
  results: PortResult[],
  color?: (state: PortResult['state'], text: string) => string,
  perRow = 16,
): string {
  const tint = color ?? ((_s, t) => t);
  const lines: string[] = [];
  for (let i = 0; i < results.length; i += perRow) {
    const row = results.slice(i, i + perRow)
      .map((r) => tint(r.state, STATE_GLYPH[r.state]))
      .join(' ');
    lines.push(`  ${String(results[i].port).padStart(5)}  ${row}`);
  }
  return lines.join('\n');
}
