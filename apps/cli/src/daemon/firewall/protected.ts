import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
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

/**
 * Shared infrastructure that is never one attacker and must never be blocked:
 * Cloudflare's published ranges (cloudflare.com/ips) and the big public
 * resolvers. A site behind Cloudflare whose nginx does not restore the real
 * client address sees every visitor as a Cloudflare edge, and one ban there
 * blocks all of them: the 2026-10-18 nichedb review found 1,514 Cloudflare
 * addresses banned by the fleet. Kept apart from DEFAULT_PROTECTED, which
 * other modules read as "local or private".
 */
export const SHARED_INFRASTRUCTURE: string[] = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
  '1.1.1.1/32', '1.0.0.1/32', '8.8.8.8/32', '8.8.4.4/32', '9.9.9.9/32',
  '149.112.112.112/32', '208.67.222.222/32', '208.67.220.220/32',
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

/**
 * Peers of SSH sessions that are open right now.
 *
 * `currentSshClient` reads `SSH_CLIENT`, which only exists when a human started
 * the daemon from their own shell. Under systemd — which is exactly when the
 * daemon runs as root and can actually write firewall rules — that variable is
 * absent, so the anti-lockout guard protected nothing at the moment it mattered
 * most. Asking the kernel who is connected works in both cases, and keeps
 * working for sessions that begin after startup.
 */
export function establishedSshPeers(): string[] {
  const peers = new Set<string>();
  try {
    const out = execFileSync('ss', ['-tnpH'], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    });
    for (const line of out.split('\n')) {
      // Match on the process rather than on port 22: sshd is frequently moved.
      if (!/users:\(\("sshd/.test(line)) continue;
      const parts = line.trim().split(/\s+/);
      const peer = parts[4];
      if (!peer) continue;
      const ip = peer.slice(0, peer.lastIndexOf(':')).replace(/^\[|\]$/g, '');
      if (ip && isIP(ip)) peers.add(ip);
    }
  } catch {
    // No `ss`, or it refused. Nothing to add.
  }
  return [...peers];
}

/**
 * The client address in an `SSH_CONNECTION` / `SSH_CLIENT` value inside a
 * NUL-separated `/proc/<pid>/environ`, or null.
 */
export function sshClientFromEnviron(environ: string): string | null {
  for (const entry of environ.split('\0')) {
    const m = /^SSH_(?:CONNECTION|CLIENT)=(\S+)/.exec(entry);
    if (m && isIP(m[1])) return m[1];
  }
  return null;
}

/**
 * Where live mosh sessions came from. mosh-server holds an unconnected UDP
 * socket, so `ss` shows no peer for it; but sshd started it, and its
 * environment still carries the SSH_CONNECTION of that login. Reading another
 * process's environ needs root, which is when bans exist at all.
 */
export function moshClients(procDir = '/proc'): string[] {
  const found = new Set<string>();
  let pids: string[] = [];
  try { pids = readdirSync(procDir).filter((p) => /^\d+$/.test(p)); } catch { return []; }
  for (const pid of pids) {
    try {
      if (readFileSync(`${procDir}/${pid}/comm`, 'utf-8').trim() !== 'mosh-server') continue;
      const ip = sshClientFromEnviron(readFileSync(`${procDir}/${pid}/environ`, 'latin1'));
      if (ip) found.add(ip);
    } catch {
      // Gone, or not readable. Nothing to add.
    }
  }
  return [...found];
}

/**
 * Key-based SSH logins in `journalctl -o short-unix` output: each client IP
 * with the newest time it logged in. Password logins are left out on purpose:
 * a guessed password is exactly the login this must not reward. So are logins
 * by a key `skip` names (by its SHA256 fingerprint): CI deploys log in with
 * keys too, from shared cloud runner addresses nobody should allowlist.
 */
export function parseKeyLogins(text: string, skip: (fingerprint: string) => boolean = () => false): Map<string, number> {
  const out = new Map<string, number>();
  for (const line of text.split('\n')) {
    const m = /^(\d+(?:\.\d+)?)\s.*Accepted publickey for \S+ from (\S+) port \d+ [^\s:]+(?:: \S+ (SHA256:\S+))?/.exec(line);
    if (!m || !isIP(m[2])) continue;
    if (m[3] && skip(m[3])) continue;
    const at = Math.round(Number(m[1]) * 1000);
    if (at > (out.get(m[2]) ?? 0)) out.set(m[2], at);
  }
  return out;
}

/** An authorized_keys comment that marks a machine, not a person. */
export function isAutomationKeyComment(comment: string): boolean {
  return /github-actions|gitlab|jenkins|buildkite|circleci|drone|\bci\b|runner|deploy|backup|automation|\bbot\b/i.test(comment);
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
