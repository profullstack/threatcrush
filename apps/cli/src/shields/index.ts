/**
 * Shields — ThreatCrush's firewall port-exposure self-test.
 *
 * An independent re-implementation of the classic ShieldsUP! idea (a trademark
 * of Gibson Research Corporation; not affiliated or endorsed): probe a
 * connection's ports from the outside and report each as Open, Closed or
 * Stealth. Shields only ever tests a connection's OWN public IPv4 address, or a
 * host whose ownership has been proven — never an arbitrary third party.
 */

import {
  ALL_SERVICE_PORTS_MAX,
  COMMON_PORTS,
  FILE_SHARING_PORTS,
  allServicePorts,
  parsePortList,
  type PortDef,
} from './ports.js';
import { scanPorts, type PortProber, type ScanOptions } from './scan.js';
import { buildShieldsReport, type ShieldsReport } from './report.js';

export type ShieldsTest = 'common' | 'all' | 'file-sharing';

export interface RunShieldsOptions extends ScanOptions {
  /** A named test (default "common"). Ignored when `ports` is given. */
  test?: ShieldsTest;
  /** An explicit port list (overrides `test`). */
  ports?: string | PortDef[];
  /** Cap for the "all" sweep (default 1055, the classic span). */
  allMax?: number;
}

export function portsForTest(opts: RunShieldsOptions = {}): PortDef[] {
  if (opts.ports) {
    return typeof opts.ports === 'string' ? parsePortList(opts.ports) : opts.ports;
  }
  switch (opts.test) {
    case 'all':
      return allServicePorts(opts.allMax ?? ALL_SERVICE_PORTS_MAX);
    case 'file-sharing':
      return FILE_SHARING_PORTS;
    case 'common':
    default:
      return COMMON_PORTS;
  }
}

export async function runShields(
  host: string,
  prober: PortProber,
  opts: RunShieldsOptions = {},
): Promise<ShieldsReport> {
  const ports = portsForTest(opts);
  const results = await scanPorts(host, ports, prober, opts);
  return buildShieldsReport(host, results);
}

export * from './ports.js';
export * from './scan.js';
export * from './report.js';
