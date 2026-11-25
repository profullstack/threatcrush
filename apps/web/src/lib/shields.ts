/**
 * Shields — ThreatCrush's firewall port-exposure self-test (server side).
 *
 * An independent re-implementation of the classic ShieldsUP! idea (a trademark
 * of Gibson Research Corporation; not affiliated or endorsed): probe the ports
 * of a connection from the outside and report each as Open, Closed or Stealth.
 *
 * SAFETY MODEL — the whole reason this is not a scan-for-hire: the web service
 * ONLY ever scans the caller's OWN public IPv4, derived from the request
 * connection. It never accepts a target address from the request body. The CLI
 * mirror of this engine lives in apps/cli/src/shields/.
 */

import net from "node:net";

export type PortState = "open" | "closed" | "stealth";

export interface PortDef {
  port: number;
  name: string;
}

export interface PortResult extends PortDef {
  state: PortState;
}

/** Classic common-ports panel plus modern services. */
export const COMMON_PORTS: PortDef[] = [
  { port: 0, name: "Reserved" }, { port: 21, name: "FTP" }, { port: 22, name: "SSH" },
  { port: 23, name: "Telnet" }, { port: 25, name: "SMTP" }, { port: 79, name: "Finger" },
  { port: 80, name: "HTTP" }, { port: 110, name: "POP3" }, { port: 113, name: "IDENT" },
  { port: 119, name: "NNTP" }, { port: 135, name: "RPC" }, { port: 139, name: "NetBIOS" },
  { port: 143, name: "IMAP" }, { port: 389, name: "LDAP" }, { port: 443, name: "HTTPS" },
  { port: 445, name: "SMB" }, { port: 500, name: "IKE" }, { port: 1433, name: "MSSQL" },
  { port: 1720, name: "H.323" }, { port: 3306, name: "MySQL" }, { port: 3389, name: "RDP" },
  { port: 5000, name: "UPnP" }, { port: 5060, name: "SIP" }, { port: 5357, name: "WSD" },
  { port: 5432, name: "PostgreSQL" }, { port: 5900, name: "VNC" }, { port: 8080, name: "HTTP-alt" },
];

export const FILE_SHARING_PORTS: PortDef[] = [
  { port: 135, name: "RPC" }, { port: 137, name: "NetBIOS-NS" }, { port: 138, name: "NetBIOS-DGM" },
  { port: 139, name: "NetBIOS-SSN" }, { port: 445, name: "SMB" },
];

export const HIGH_RISK_OPEN = new Set<number>([23, 135, 137, 138, 139, 445, 1433, 3306, 5432, 3389, 5900]);

export const ALL_SERVICE_PORTS_MAX = 1055;

export type ShieldsTest = "common" | "all" | "file-sharing";

export function portsForTest(test: ShieldsTest): PortDef[] {
  if (test === "file-sharing") return FILE_SHARING_PORTS;
  if (test === "all") {
    const out: PortDef[] = [];
    for (let p = 0; p <= ALL_SERVICE_PORTS_MAX; p++) out.push({ port: p, name: "" });
    return out;
  }
  return COMMON_PORTS;
}

/** Probe one TCP port: connect→open, RST→closed, timeout→stealth. Never throws. */
export function probeTcp(host: string, port: number, timeoutMs: number): Promise<PortState> {
  return new Promise<PortState>((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (state: PortState) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(state);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish("open"));
    socket.once("timeout", () => finish("stealth"));
    socket.once("error", (err: NodeJS.ErrnoException) =>
      finish(err.code === "ECONNREFUSED" ? "closed" : "stealth"));
    try {
      socket.connect(port, host);
    } catch {
      finish("stealth");
    }
  });
}

export interface ShieldsSummary {
  total: number;
  open: number;
  closed: number;
  stealth: number;
  grade: "stealth" | "good" | "warning" | "danger";
  verdict: string;
}

export interface ShieldsScan {
  target: string;
  test: ShieldsTest;
  ports: PortResult[];
  summary: ShieldsSummary;
}

export async function scanClientPorts(
  host: string,
  test: ShieldsTest,
  opts: { concurrency?: number; timeoutMs?: number } = {},
): Promise<ShieldsScan> {
  const ports = portsForTest(test);
  const concurrency = Math.max(1, opts.concurrency ?? 64);
  const timeoutMs = opts.timeoutMs ?? 3000;
  const results: PortResult[] = new Array(ports.length);
  let next = 0;

  async function worker(): Promise<void> {
    while (true) {
      const i = next++;
      if (i >= ports.length) return;
      const def = ports[i];
      let state: PortState = "stealth";
      try {
        state = await probeTcp(host, def.port, timeoutMs);
      } catch {
        state = "stealth";
      }
      results[i] = { ...def, state };
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(concurrency, ports.length) }, () => worker()),
  );

  return { target: host, test, ports: results, summary: grade(results) };
}

function grade(results: PortResult[]): ShieldsSummary {
  const open = results.filter((r) => r.state === "open");
  const closed = results.filter((r) => r.state === "closed");
  const stealth = results.filter((r) => r.state === "stealth");
  const anyHighRisk = open.some((r) => HIGH_RISK_OPEN.has(r.port));

  let g: ShieldsSummary["grade"];
  let verdict: string;
  if (open.length === 0 && closed.length === 0) {
    g = "stealth";
    verdict = "Perfect stealth — every tested port was invisible to the Internet.";
  } else if (open.length === 0) {
    g = "good";
    verdict = `No open ports, but ${closed.length} replied "closed", so your machine is visible. True stealth drops those silently.`;
  } else if (anyHighRisk) {
    g = "danger";
    verdict = `${open.length} OPEN port(s), including high-risk services. Close or firewall these now.`;
  } else {
    g = "warning";
    verdict = `${open.length} OPEN port(s) reachable from the Internet. Confirm each is meant to be exposed.`;
  }
  return { total: results.length, open: open.length, closed: closed.length, stealth: stealth.length, grade: g, verdict };
}

/**
 * Derive the caller's own public IPv4 from the request headers set by our edge
 * (Cloudflare / nginx). Returns null for private/invalid/IPv6-only callers.
 */
export function clientIpv4(headers: Headers): string | null {
  const candidates = [
    headers.get("cf-connecting-ip"),
    headers.get("x-real-ip"),
    (headers.get("x-forwarded-for") ?? "").split(",")[0]?.trim(),
  ];
  for (const c of candidates) {
    if (c && /^\d{1,3}(\.\d{1,3}){3}$/.test(c) && !isPrivateV4(c)) return c;
  }
  return null;
}

function isPrivateV4(ip: string): boolean {
  const [a, b] = ip.split(".").map(Number);
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}
