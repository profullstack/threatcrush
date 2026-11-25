/**
 * Port catalogues for the Shields port-exposure self-test.
 *
 * Shields is ThreatCrush's clone of the classic firewall self-test popularised
 * by GRC's ShieldsUP! — it probes the ports of a connection from the outside and
 * reports each as Open, Closed or Stealth. "ShieldsUP!" is a trademark of
 * Gibson Research Corporation; this is an independent re-implementation of the
 * idea, not affiliated with or endorsed by GRC.
 *
 * Like the original, Shields only ever tests a connection's *own* public IPv4
 * address (the source IP of the request, or a host whose ownership has been
 * proven). It never scans an address the caller does not control.
 */

export interface PortDef {
  port: number;
  /** Short service label shown next to the port. */
  name: string;
}

/**
 * The "Common Ports" set: the most frequently probed and exploited TCP service
 * ports, mirroring the classic ShieldsUP! common-ports panel plus a few modern
 * additions (SIP, WSD, RDP, common databases).
 */
export const COMMON_PORTS: PortDef[] = [
  { port: 0, name: 'Reserved' },
  { port: 21, name: 'FTP' },
  { port: 22, name: 'SSH' },
  { port: 23, name: 'Telnet' },
  { port: 25, name: 'SMTP' },
  { port: 79, name: 'Finger' },
  { port: 80, name: 'HTTP' },
  { port: 110, name: 'POP3' },
  { port: 113, name: 'IDENT' },
  { port: 119, name: 'NNTP' },
  { port: 135, name: 'RPC' },
  { port: 139, name: 'NetBIOS' },
  { port: 143, name: 'IMAP' },
  { port: 389, name: 'LDAP' },
  { port: 443, name: 'HTTPS' },
  { port: 445, name: 'SMB' },
  { port: 500, name: 'IKE' },
  { port: 1002, name: 'ILS' },
  { port: 1024, name: 'DCOM' },
  { port: 1025, name: 'Host' },
  { port: 1026, name: 'Host' },
  { port: 1027, name: 'Host' },
  { port: 1028, name: 'Host' },
  { port: 1029, name: 'Host' },
  { port: 1030, name: 'Host' },
  { port: 1433, name: 'MSSQL' },
  { port: 1720, name: 'H.323' },
  { port: 3306, name: 'MySQL' },
  { port: 3389, name: 'RDP' },
  { port: 5000, name: 'UPnP' },
  { port: 5060, name: 'SIP' },
  { port: 5357, name: 'WSD' },
  { port: 5432, name: 'PostgreSQL' },
  { port: 5900, name: 'VNC' },
  { port: 8080, name: 'HTTP-alt' },
];

/**
 * File-sharing ports (NetBIOS / SMB). An open port here is the classic
 * Windows file-and-printer-sharing exposure and is treated as high severity.
 */
export const FILE_SHARING_PORTS: PortDef[] = [
  { port: 135, name: 'RPC' },
  { port: 137, name: 'NetBIOS-NS' },
  { port: 138, name: 'NetBIOS-DGM' },
  { port: 139, name: 'NetBIOS-SSN' },
  { port: 445, name: 'SMB' },
];

/**
 * Open ports on these services are the most dangerous to expose, so Shields
 * grades them high rather than medium.
 */
export const HIGH_RISK_OPEN = new Set<number>([
  23, // Telnet
  135, 137, 138, 139, 445, // file sharing
  1433, 3306, 5432, // databases
  3389, // RDP
  5900, // VNC
]);

/**
 * The "All Service Ports" sweep: TCP 0–1055 inclusive (1056 ports), the same
 * span the classic test covers. Service ports above 1055 are not tested.
 */
export const ALL_SERVICE_PORTS_MAX = 1055;

export function allServicePorts(max: number = ALL_SERVICE_PORTS_MAX): PortDef[] {
  const out: PortDef[] = [];
  for (let p = 0; p <= max; p++) out.push({ port: p, name: '' });
  return out;
}

/** Parse a comma/space/range list like "22,80,443,8000-8010" into PortDefs. */
export function parsePortList(spec: string): PortDef[] {
  const seen = new Set<number>();
  const out: PortDef[] = [];
  for (const token of spec.split(/[\s,]+/).filter(Boolean)) {
    const range = token.match(/^(\d+)-(\d+)$/);
    if (range) {
      const lo = Number(range[1]);
      const hi = Number(range[2]);
      for (let p = Math.min(lo, hi); p <= Math.max(lo, hi); p++) addPort(out, seen, p);
    } else if (/^\d+$/.test(token)) {
      addPort(out, seen, Number(token));
    }
  }
  return out;
}

function addPort(out: PortDef[], seen: Set<number>, p: number): void {
  if (p < 0 || p > 65535 || seen.has(p)) return;
  seen.add(p);
  const known = COMMON_PORTS.find((d) => d.port === p);
  out.push({ port: p, name: known?.name ?? '' });
}
