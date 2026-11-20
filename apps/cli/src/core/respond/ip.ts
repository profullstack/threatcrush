import { isIP } from 'node:net';
import { DEFAULT_PROTECTED, SHARED_INFRASTRUCTURE, ipMatches } from '../../daemon/firewall/protected.js';
import type { ConnRow } from './types.js';

/**
 * Why `ip` must never be the target of `respond ip`, or null when it may be.
 * Private ranges, loopback, shared infrastructure (Cloudflare, public
 * resolvers), the host's gateways, an operator allowlist, and the address of
 * the session running this command (the classic self-lockout).
 */
export function refuseIp(
  ip: string,
  ctx: { gateways?: string[]; allowlist?: string[]; ownClient?: string | null },
): string | null {
  if (isIP(ip) === 0) return `not an IP address: ${ip}`;
  const hit = (list: string[]) => list.find((entry) => ipMatches(ip, entry));
  let m = hit(DEFAULT_PROTECTED);
  if (m) return `${ip} is in a private/loopback range (${m}); refusing`;
  m = hit(SHARED_INFRASTRUCTURE);
  if (m) return `${ip} is shared infrastructure (${m}); banning it would block everyone behind it`;
  if (ctx.gateways?.includes(ip)) return `${ip} is this host's default gateway`;
  m = hit(ctx.allowlist ?? []);
  if (m) return `${ip} is on the protected list (${m})`;
  if (ctx.ownClient && ctx.ownClient === ip) return `${ip} is the address of the session running this command`;
  return null;
}

/** Established TCP connections from `ss -tnpH` (with the State column). */
export function parseSs(text: string): ConnRow[] {
  const out: ConnRow[] = [];
  for (const raw of text.split('\n')) {
    const parts = raw.trim().split(/\s+/);
    if (parts.length < 5 || parts[0] !== 'ESTAB') continue;
    const processes: Array<{ name: string; pid: number }> = [];
    const rest = parts.slice(5).join(' ');
    for (const m of rest.matchAll(/\("([^"]+)",pid=(\d+)/g)) processes.push({ name: m[1], pid: Number(m[2]) });
    out.push({ local: parts[3], peer: parts[4], processes });
  }
  return out;
}

/** The address part of `1.2.3.4:22`, `[2001:db8::1]:22` or `::ffff:1.2.3.4:22`. */
export function peerIp(peer: string): string {
  const host = peer.slice(0, peer.lastIndexOf(':')).replace(/^\[|\]$/g, '');
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(host);
  return mapped ? mapped[1] : host.split('%')[0];
}

export function connectionsFrom(conns: ConnRow[], ip: string): ConnRow[] {
  return conns.filter((c) => peerIp(c.peer) === ip);
}

/**
 * Per-connection sshd processes to kill for an address. Only processes named
 * sshd / sshd-session that hold a socket to that peer: the listener holds no
 * established socket, so it is never in this list.
 */
export function sshdSessionPids(conns: ConnRow[], protect: number[] = []): number[] {
  const pids = new Set<number>();
  for (const c of conns) {
    for (const p of c.processes) {
      if (/^sshd(-session)?$/.test(p.name) && p.pid > 1 && !protect.includes(p.pid)) pids.add(p.pid);
    }
  }
  return [...pids].sort((a, b) => a - b);
}
