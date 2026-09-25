import { execFileSync } from 'node:child_process';
import { isIP } from 'node:net';

/**
 * PRD 0010 R1: the set of addresses that can never be blocked, enforced at the
 * point of writing a rule rather than at the point of deciding. Auto-defence is
 * on by default now, so this list is the only thing standing between a wrong
 * detection and an operator locked out of their own box at 3am.
 */
export const DEFAULT_PROTECTED: string[] = [
  '127.0.0.0/8',
  '::1/128',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  'fc00::/7',
  'fe80::/10',
];

/** Bytes of an IPv4 or IPv6 address, or null when it is neither. */
export function ipToBytes(ip: string): Uint8Array | null {
  const version = isIP(ip);
  if (version === 4) return v4ToBytes(ip);
  if (version === 6) return v6ToBytes(ip);
  return null;
}

function v4ToBytes(ip: string): Uint8Array | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    bytes[i] = n;
  }
  return bytes;
}

function v6ToBytes(ip: string): Uint8Array | null {
  // Strip a zone id (fe80::1%eth0) — it is an interface, not an address.
  const bare = ip.split('%')[0];
  const [headText, tailText] = bare.split('::', 2);
  const head = headText ? headText.split(':') : [];
  const tail = tailText !== undefined ? (tailText ? tailText.split(':') : []) : null;

  const groups: number[] = [];
  const pushGroup = (group: string): boolean => {
    // A trailing IPv4 form (::ffff:192.0.2.1) is two groups, not one.
    if (group.includes('.')) {
      const v4 = v4ToBytes(group);
      if (!v4) return false;
      groups.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      return true;
    }
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return false;
    groups.push(parseInt(group, 16));
    return true;
  };

  for (const group of head) if (!pushGroup(group)) return null;
  const headCount = groups.length;

  if (tail === null) {
    if (headCount !== 8) return null;
  } else {
    const tailGroups: number[] = [];
    const saved = groups.length;
    for (const group of tail) if (!pushGroup(group)) return null;
    tailGroups.push(...groups.splice(saved));
    const zeros = 8 - headCount - tailGroups.length;
    if (zeros < 0) return null;
    for (let i = 0; i < zeros; i++) groups.push(0);
    groups.push(...tailGroups);
  }

  if (groups.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = (groups[i] >> 8) & 0xff;
    bytes[i * 2 + 1] = groups[i] & 0xff;
  }
  return bytes;
}

/**
 * Does `ip` fall inside `entry`? `entry` is a bare address or a CIDR. A v4
 * address never matches a v6 range, and vice versa — mixing the families is how
 * a "protected" check quietly passes something it meant to stop.
 */
export function ipMatches(ip: string, entry: string): boolean {
  const [network, prefixText] = entry.trim().split('/');
  const target = ipToBytes(ip);
  const base = ipToBytes(network);
  if (!target || !base || target.length !== base.length) return false;

  const bits = prefixText === undefined ? base.length * 8 : Number(prefixText);
  if (!Number.isInteger(bits) || bits < 0 || bits > base.length * 8) return false;

  const wholeBytes = Math.floor(bits / 8);
  for (let i = 0; i < wholeBytes; i++) {
    if (target[i] !== base[i]) return false;
  }
  const remainder = bits % 8;
  if (remainder === 0) return true;
  const mask = 0xff << (8 - remainder) & 0xff;
  return (target[wholeBytes] & mask) === (base[wholeBytes] & mask);
}

/** True when any entry in `list` covers `ip`. */
export function isProtected(ip: string, list: string[]): boolean {
  return list.some((entry) => ipMatches(ip, entry));
}

/**
 * The address of whoever started the daemon over SSH. Blocking it is the
 * classic self-lockout, so it joins the protected set for the life of the
 * process.
 */
export function currentSshClient(env: NodeJS.ProcessEnv = process.env): string | null {
  const source = env.SSH_CLIENT || env.SSH_CONNECTION;
  if (!source) return null;
  const ip = source.trim().split(/\s+/)[0];
  return ip && isIP(ip) ? ip : null;
}

/** Default gateway(s), so a misread of upstream traffic cannot cut the route. */
export function defaultGateways(): string[] {
  const found = new Set<string>();
  for (const args of [['-4', 'route', 'show', 'default'], ['-6', 'route', 'show', 'default']]) {
    try {
      const out = execFileSync('ip', args, { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
      for (const line of out.split('\n')) {
        const match = line.match(/\bvia\s+(\S+)/);
        if (match && isIP(match[1])) found.add(match[1]);
      }
    } catch {
      // No `ip` command, or no default route. Nothing to protect here.
    }
  }
  return [...found];
}
