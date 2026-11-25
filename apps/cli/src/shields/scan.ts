/**
 * The Shields scanner: probe a list of TCP ports on a host and classify each
 * as Open, Closed or Stealth, exactly like the classic ShieldsUP! firewall
 * self-test.
 *
 * The transport is injected (`prober`), so the scoring logic is pure and
 * testable, and the same engine drives a real socket probe (CLI / server) or a
 * fake in tests. The real prober lives in `tcpProber` and uses Node sockets; it
 * is only imported where a socket is available.
 */

import type { PortDef } from './ports.js';

/**
 * - `open`    the host accepted the TCP connection — the port is reachable.
 * - `closed`  the host actively refused (RST / ECONNREFUSED) — reachable but
 *             nothing is listening; the machine is visible to the Internet.
 * - `stealth` no response at all before the timeout — a firewall dropped the
 *             packet; the port (and ideally the machine) is invisible.
 */
export type PortState = 'open' | 'closed' | 'stealth';

/** Probes one TCP port and returns its state. Never throws. */
export type PortProber = (host: string, port: number, timeoutMs: number) => Promise<PortState>;

export interface PortResult extends PortDef {
  state: PortState;
}

export interface ScanOptions {
  /** How many ports to probe at once. Default 64 (matches the classic grid). */
  concurrency?: number;
  /** Per-port timeout in ms. Default 3000. */
  timeoutMs?: number;
  /** Called after each port resolves, for progress UIs. */
  onPort?: (r: PortResult, done: number, total: number) => void;
  /** Abort signal to stop a long sweep early. */
  signal?: AbortSignal;
}

export async function scanPorts(
  host: string,
  ports: PortDef[],
  prober: PortProber,
  opts: ScanOptions = {},
): Promise<PortResult[]> {
  const concurrency = Math.max(1, opts.concurrency ?? 64);
  const timeoutMs = opts.timeoutMs ?? 3000;
  const results: PortResult[] = new Array(ports.length);
  let next = 0;
  let done = 0;

  async function worker(): Promise<void> {
    while (true) {
      if (opts.signal?.aborted) return;
      const i = next++;
      if (i >= ports.length) return;
      const def = ports[i];
      let state: PortState = 'stealth';
      try {
        state = await prober(host, def.port, timeoutMs);
      } catch {
        state = 'stealth';
      }
      const r: PortResult = { ...def, state };
      results[i] = r;
      done++;
      opts.onPort?.(r, done, ports.length);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, ports.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

export interface ShieldsSummary {
  total: number;
  open: number;
  closed: number;
  stealth: number;
  openPorts: PortResult[];
  /** One of the ShieldsUP!-style overall grades. */
  grade: 'stealth' | 'good' | 'warning' | 'danger';
  verdict: string;
}

/**
 * Grade a completed scan the way the classic test does:
 *  - every port stealth              → perfect stealth ("TruStealth"-style pass)
 *  - no open ports, some closed      → good, but the machine is visible
 *  - open ports, none high-risk      → warning
 *  - any high-risk open port         → danger
 */
export function summarizeShields(results: PortResult[], highRisk: Set<number>): ShieldsSummary {
  const open = results.filter((r) => r.state === 'open');
  const closed = results.filter((r) => r.state === 'closed');
  const stealth = results.filter((r) => r.state === 'stealth');
  const anyHighRisk = open.some((r) => highRisk.has(r.port));

  let grade: ShieldsSummary['grade'];
  let verdict: string;
  if (open.length === 0 && closed.length === 0) {
    grade = 'stealth';
    verdict = 'Perfect stealth — every tested port was invisible to the Internet. Nothing responded.';
  } else if (open.length === 0) {
    grade = 'good';
    verdict = `No open ports, but ${closed.length} port(s) replied "closed", so your machine is visible to the Internet. True stealth would drop those silently.`;
  } else if (anyHighRisk) {
    grade = 'danger';
    verdict = `${open.length} OPEN port(s), including high-risk services. Close or firewall these now.`;
  } else {
    grade = 'warning';
    verdict = `${open.length} OPEN port(s) are reachable from the Internet. Confirm each one is meant to be exposed.`;
  }

  return {
    total: results.length,
    open: open.length,
    closed: closed.length,
    stealth: stealth.length,
    openPorts: open,
    grade,
    verdict,
  };
}
