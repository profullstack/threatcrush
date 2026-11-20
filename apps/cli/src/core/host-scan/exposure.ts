/**
 * `network-exposure` host check: datastore / admin ports listening on a public
 * address with nothing in the firewall blocking them.
 *
 * Two traps this exists for:
 *  - Docker-published ports bypass ufw and the INPUT chain entirely. Only the
 *    DOCKER-USER chain (FORWARD path) can stop them, and it sees packets AFTER
 *    DNAT: `-p 6543:6432` arrives there with `--dport 6432`, so a rule written
 *    as `--dport 6543` never matches. `-m conntrack --ctorigdstport 6543`
 *    matches the original (host) port.
 *  - DOCKER-USER rules added by hand live only in the kernel. Nothing restores
 *    them at boot unless a unit, script or rules.v4 does, so a reboot reopens
 *    every port they were closing.
 *
 * Everything below the orchestrator is pure (text in, data out) so the tests
 * can replay real `ss`, `docker ps`, `iptables -S`, `ufw status` and `nft`
 * output.
 */
import { existsSync, readdirSync, readlinkSync, statSync } from 'node:fs';
import type { CheckItem, CheckResult, HostContext } from './checks.js';
import { sysRead, sysRun, sysWhich } from './sys.js';

// ─── sensitive ports ───

export const SENSITIVE_PORTS: Record<number, string> = {
  5432: 'postgres', 6432: 'pgbouncer', 6543: 'postgres pooler',
  3306: 'mysql', 33060: 'mysql x', 27017: 'mongodb', 6379: 'redis',
  9200: 'elasticsearch', 9300: 'elasticsearch transport',
  8123: 'clickhouse http', 9000: 'clickhouse native', 5984: 'couchdb', 11211: 'memcached',
  7687: 'neo4j bolt', 7474: 'neo4j http', 8086: 'influxdb',
  5672: 'rabbitmq', 15672: 'rabbitmq admin', 9092: 'kafka', 2379: 'etcd',
  2375: 'docker API (no TLS)', 2376: 'docker API', 10250: 'kubelet', 631: 'cups',
};

export function sensitiveService(port: number | undefined): string | null {
  return port !== undefined ? SENSITIVE_PORTS[port] ?? null : null;
}

// ─── addresses ───

function stripAddr(a: string): string {
  return a.replace(/^\[|\]$/g, '').replace(/%[^%]*$/, '');
}

export function isLoopback(addr: string): boolean {
  const a = stripAddr(addr).toLowerCase();
  return a.startsWith('127.') || a === '::1' || a.startsWith('::ffff:127.') || a === 'localhost';
}

export function isWildcard(addr: string): boolean {
  const a = stripAddr(addr);
  return a === '0.0.0.0' || a === '*' || a === '::' || a === '';
}

/** RFC1918, CGNAT, link-local, ULA: reachable only from a private network. */
export function isPrivate(addr: string): boolean {
  const a = stripAddr(addr).toLowerCase().replace(/^::ffff:/, '');
  const m = /^(\d+)\.(\d+)\.\d+\.\d+$/.exec(a);
  if (m) {
    const [x, y] = [Number(m[1]), Number(m[2])];
    return x === 10 || (x === 172 && y >= 16 && y <= 31) || (x === 192 && y === 168) || (x === 100 && y >= 64 && y <= 127) || (x === 169 && y === 254);
  }
  return /^f[cd][0-9a-f]{2}:/.test(a) || /^fe[89ab][0-9a-f]:/.test(a);
}

// ─── listeners: ss -tlnpH, /proc/net/tcp ───

export interface Listener {
  addr: string;
  port: number;
  /** 4, 6, or 46 for a dual-stack `*` socket. */
  family: 4 | 6 | 46;
  process?: string;
  pid?: number;
}

function familyOf(addr: string): 4 | 6 | 46 {
  if (addr === '*') return 46;
  return addr.includes(':') ? 6 : 4;
}

/** Parse `ss -tlnH` / `ss -tlnpH` output. */
export function parseSsListeners(text: string): Listener[] {
  const out: Listener[] = [];
  for (const raw of text.split('\n')) {
    const cols = raw.trim().split(/\s+/);
    if (cols.length < 4) continue;
    // With -H: State Recv-Q Send-Q Local Peer [Process]; tolerate a missing State column.
    const idx = /^\d+$/.test(cols[0]) ? 2 : 3;
    const local = cols[idx];
    const m = local && /^(.*):(\d+|\*)$/.exec(local);
    if (!m || m[2] === '*') continue;
    const addr = stripAddr(m[1]);
    const proc = /users:\(\("([^"]+)",pid=(\d+)/.exec(raw);
    out.push({ addr, port: Number(m[2]), family: familyOf(addr), process: proc?.[1], pid: proc ? Number(proc[2]) : undefined });
  }
  return out;
}

function hexToV4(h: string): string {
  const n = parseInt(h, 16);
  return [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255].join('.');
}

function hexToV6(h: string): string {
  const groups: string[] = [];
  for (let w = 0; w < 4; w++) {
    const word = h.slice(w * 8, w * 8 + 8);
    const bytes = word.match(/../g)!.reverse().join('');
    groups.push(bytes.slice(0, 4), bytes.slice(4, 8));
  }
  const full = groups.map((g) => g.replace(/^0+(?=.)/, '')).join(':');
  if (/^(0:){7}0$/.test(full)) return '::';
  if (/^(0:){7}1$/.test(full)) return '::1';
  const v4mapped = /^0:0:0:0:0:ffff:([0-9a-f]+):([0-9a-f]+)$/.exec(full);
  if (v4mapped) {
    const hi = parseInt(v4mapped[1], 16); const lo = parseInt(v4mapped[2], 16);
    return `::ffff:${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return full;
}

/** Parse /proc/net/tcp or /proc/net/tcp6 (LISTEN rows only). Returns inode for the pid map. */
export function parseProcNetTcp(text: string, family: 4 | 6): Array<Listener & { inode: string }> {
  const out: Array<Listener & { inode: string }> = [];
  for (const line of text.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 10 || f[3] !== '0A') continue;
    const [hexAddr, hexPort] = f[1].split(':');
    const addr = family === 4 ? hexToV4(hexAddr) : hexToV6(hexAddr);
    out.push({ addr, port: parseInt(hexPort, 16), family, inode: f[9] });
  }
  return out;
}

// ─── docker ps port bindings ───

export interface DockerPortMapping {
  container: string;
  hostIp: string;
  hostPort: number;
  containerPort: number;
  proto: string;
  family: 4 | 6;
}

/** Parse `docker ps --format '{{.Names}}\t{{.Ports}}'`. Port ranges are expanded (capped at 1024 per binding). */
export function parseDockerPsPorts(text: string): DockerPortMapping[] {
  const out: DockerPortMapping[] = [];
  for (const line of text.split('\n')) {
    const tab = line.indexOf('\t');
    if (tab < 0) continue;
    const container = line.slice(0, tab).trim();
    for (const spec of line.slice(tab + 1).split(',').map((s) => s.trim()).filter(Boolean)) {
      const m = /^(.*):(\d+)(?:-(\d+))?->(\d+)(?:-(\d+))?\/(\w+)$/.exec(spec);
      if (!m) continue; // "5432/tcp": exposed, not published
      const hostIp = stripAddr(m[1]) || '0.0.0.0';
      const h0 = Number(m[2]); const h1 = m[3] ? Number(m[3]) : h0;
      const c0 = Number(m[4]);
      for (let i = 0; i <= Math.min(h1 - h0, 1023); i++) {
        out.push({ container, hostIp, hostPort: h0 + i, containerPort: c0 + i, proto: m[6], family: hostIp.includes(':') ? 6 : 4 });
      }
    }
  }
  return out;
}

// ─── exposures ───

export interface Exposure {
  kind: 'docker' | 'host';
  addr: string;
  family: 4 | 6;
  /** Port on the host (what the internet connects to). */
  hostPort: number;
  /** Port inside the container (what DOCKER-USER sees after DNAT). */
  containerPort?: number;
  container?: string;
  process?: string;
  pid?: number;
  service: string;
}

export interface ClassifyOptions {
  /** The host has a global IPv6 address; without one, IPv6 bindings are unreachable. */
  hasGlobalV6: boolean;
  /** `docker ps` ran, so docker-proxy listeners are covered by the mappings. */
  dockerKnown: boolean;
}

/**
 * Pick out the sensitive services reachable on a public address. A Docker
 * mapping is sensitive when either its host port or its CONTAINER port is a
 * datastore port: `-p 5601:5432` is postgres even though 5601 is not.
 */
export function classifyExposures(listeners: Listener[], mappings: DockerPortMapping[], opts: ClassifyOptions): { sensitive: Exposure[]; publicCount: number } {
  const sensitive: Exposure[] = [];
  const seen = new Set<string>();
  let publicCount = 0;
  const reachable = (addr: string, family: 4 | 6) => !isLoopback(addr) && !isPrivate(addr) && (family === 4 || opts.hasGlobalV6);
  const add = (e: Exposure) => {
    const key = `${e.kind}|${e.family}|${e.hostPort}`;
    if (seen.has(key)) return;
    seen.add(key);
    sensitive.push(e);
  };
  const dockerHostPorts = new Set<string>();
  for (const m of mappings) {
    if (m.proto !== 'tcp') continue;
    dockerHostPorts.add(`${m.family}|${m.hostPort}`);
    if (!reachable(m.hostIp, m.family)) continue;
    publicCount++;
    const service = sensitiveService(m.containerPort) ?? sensitiveService(m.hostPort);
    if (!service) continue;
    add({ kind: 'docker', addr: m.hostIp, family: m.family, hostPort: m.hostPort, containerPort: m.containerPort, container: m.container, service });
  }
  for (const l of listeners) {
    for (const family of l.family === 46 ? [4, 6] as const : [l.family]) {
      if (!reachable(l.addr, family)) continue;
      if (l.process === 'docker-proxy' && opts.dockerKnown) continue; // covered by the mappings above
      if (dockerHostPorts.has(`${family}|${l.port}`)) continue;
      publicCount++;
      const service = sensitiveService(l.port);
      if (!service) continue;
      if (l.process === 'docker-proxy') {
        add({ kind: 'docker', addr: l.addr, family, hostPort: l.port, process: l.process, pid: l.pid, service });
      } else {
        add({ kind: 'host', addr: l.addr, family, hostPort: l.port, process: l.process, pid: l.pid, service });
      }
    }
  }
  return { sensitive, publicCount };
}

// ─── iptables -S ───

type PortRange = [number, number];

export interface IptRule {
  raw: string;
  target: string | null;
  proto: string | null;
  dports: PortRange[] | null;
  ctorigdstports: PortRange[] | null;
  source: string | null;
  sourceNegated: boolean;
  iface: string | null;
  ifaceNegated: boolean;
  states: string[] | null;
  /** Has a negated port match or another construct this evaluator does not model. */
  opaque: boolean;
}

export interface IptChain { policy: string | null; rules: IptRule[] }

function parsePorts(spec: string): PortRange[] {
  return spec.split(',').filter(Boolean).map((p) => {
    const [a, b] = p.split(':');
    return [Number(a), Number(b ?? a)] as PortRange;
  });
}

function parseIptRule(line: string): IptRule {
  const t = line.trim().split(/\s+/);
  const rule: IptRule = { raw: line.trim(), target: null, proto: null, dports: null, ctorigdstports: null, source: null, sourceNegated: false, iface: null, ifaceNegated: false, states: null, opaque: false };
  let neg = false;
  for (let i = 2; i < t.length; i++) {
    const tok = t[i];
    if (tok === '!') { neg = true; continue; }
    const next = t[i + 1];
    switch (tok) {
      case '-j': case '-g': rule.target = next; i++; break;
      case '-p': rule.proto = next; i++; break;
      case '-s': rule.source = next; rule.sourceNegated = neg; i++; break;
      case '-i': rule.iface = next; rule.ifaceNegated = neg; i++; break;
      case '--dport': case '--dports': case '--destination-port': case '--destination-ports':
        if (neg) rule.opaque = true; else rule.dports = [...(rule.dports ?? []), ...parsePorts(next)];
        i++; break;
      case '--ctorigdstport':
        if (neg) rule.opaque = true; else rule.ctorigdstports = [...(rule.ctorigdstports ?? []), ...parsePorts(next)];
        i++; break;
      case '--ctstate': case '--state': rule.states = next.split(','); i++; break;
      default: break;
    }
    neg = false;
  }
  return rule;
}

/** Parse the `-P` / `-A` lines of `iptables -S [CHAIN]` (or iptables-save) for one chain. */
export function parseIptablesChain(text: string, chain: string): IptChain {
  let policy: string | null = null;
  const rules: IptRule[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    const p = new RegExp(`^(?:-P\\s+|:)${chain}\\s+(\\S+)`).exec(line);
    if (p) { if (p[1] !== '-') policy = p[1]; continue; }
    if (line.startsWith(`-A ${chain} `) || line === `-A ${chain}`) rules.push(parseIptRule(line));
  }
  return { policy, rules };
}

/** True when the chain has nothing but an unconditional RETURN (Docker's default). */
export function isEmptyDockerUser(chain: IptChain): boolean {
  return chain.rules.every((r) => r.target === 'RETURN' && !r.dports && !r.ctorigdstports && !r.source && !r.iface && !r.proto);
}

const inRange = (port: number, ranges: PortRange[]) => ranges.some(([a, b]) => port >= a && port <= b);
const anySource = (s: string | null) => !s || s === '0.0.0.0/0' || s === '::/0';

export interface FirewallVerdict {
  verdict: 'blocked' | 'open' | 'unknown';
  /** The rule or policy that decided it. */
  by: string;
  /** Sources an earlier ACCEPT lets through before the block. */
  allowlisted?: string[];
}

/**
 * Walk a chain first-match for a new TCP connection. `dport` is the port the
 * chain sees (the container port in DOCKER-USER, after DNAT); `origDport` is
 * the port the client dialled (the host port), matched by --ctorigdstport.
 * A chain without a policy (DOCKER-USER) falls through to "open".
 */
export function evaluateIptChain(chain: IptChain, pkt: { dport: number; origDport: number }, fallThrough: 'open' | 'policy' = 'policy'): FirewallVerdict {
  const allowlisted: string[] = [];
  for (const r of chain.rules) {
    if (r.opaque) continue;
    if (r.proto && r.proto !== 'tcp' && r.proto !== 'all' && r.proto !== '6') continue;
    if (r.dports && !inRange(pkt.dport, r.dports)) continue;
    if (r.ctorigdstports && !inRange(pkt.origDport, r.ctorigdstports)) continue;
    if (r.states && !r.states.includes('NEW')) continue;
    if (r.iface && !r.ifaceNegated && r.iface === 'lo') continue;
    const target = (r.target ?? '').toUpperCase();
    const blocks = target === 'DROP' || target === 'REJECT';
    const passes = target === 'ACCEPT' || target === 'RETURN';
    if (!blocks && !passes) continue; // LOG, jumps to custom chains: not modelled
    if (target === 'RETURN' && fallThrough === 'policy') continue;
    if (!anySource(r.source) && !r.sourceNegated) {
      // Only some sources: an ACCEPT is an allowlist, a DROP blocks only them.
      if (passes) allowlisted.push(r.source!);
      continue;
    }
    return { verdict: blocks ? 'blocked' : 'open', by: r.raw, allowlisted: allowlisted.length ? allowlisted : undefined };
  }
  if (fallThrough === 'open' || !chain.policy) return { verdict: 'open', by: 'end of chain (falls through to Docker\'s ACCEPT)', allowlisted: allowlisted.length ? allowlisted : undefined };
  const p = chain.policy.toUpperCase();
  return { verdict: p === 'DROP' || p === 'REJECT' ? 'blocked' : 'open', by: `policy ${p}`, allowlisted: allowlisted.length ? allowlisted : undefined };
}

export interface IneffectiveRule { rule: string; hostPort: number; containerPort: number; container: string }

/**
 * DOCKER-USER rules that match `--dport <hostPort>` for a mapping whose
 * container port differs: after DNAT the packet carries the container port, so
 * the rule never fires (the 5601->5432 trap).
 */
export function findIneffectiveDockerUserRules(chain: IptChain, mappings: DockerPortMapping[]): IneffectiveRule[] {
  const out: IneffectiveRule[] = [];
  const containerPorts = new Set(mappings.map((m) => m.containerPort));
  for (const r of chain.rules) {
    if (!r.dports || r.ctorigdstports) continue;
    for (const m of mappings) {
      if (m.hostPort === m.containerPort || containerPorts.has(m.hostPort)) continue;
      if (inRange(m.hostPort, r.dports) && !inRange(m.containerPort, r.dports)) {
        if (!out.some((o) => o.rule === r.raw && o.hostPort === m.hostPort)) out.push({ rule: r.raw, hostPort: m.hostPort, containerPort: m.containerPort, container: m.container });
      }
    }
  }
  return out;
}

// ─── ufw status verbose ───

export interface UfwRule { to: string; action: string; from: string; v6: boolean }
export interface UfwStatus { active: boolean; defaultIncoming: string | null; rules: UfwRule[] }

export function parseUfwStatus(text: string): UfwStatus {
  const active = /^Status:\s*active/m.test(text);
  const def = /^Default:\s*(\w+)\s*\(incoming\)/m.exec(text);
  const rules: UfwRule[] = [];
  let inTable = false;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\s+#.*$/, '').trimEnd();
    if (/^--\s+/.test(line)) { inTable = true; continue; }
    if (!inTable || !line.trim()) continue;
    const cols = line.split(/\s{2,}/).map((s) => s.trim()).filter(Boolean);
    if (cols.length < 3) continue;
    const [to, action, from] = cols;
    rules.push({ to, action: action.toUpperCase(), from, v6: /\(v6\)/.test(to) || /\(v6\)/.test(from) });
  }
  return { active, defaultIncoming: def ? def[1].toLowerCase() : null, rules };
}

function ufwToMatches(to: string, port: number): boolean {
  const spec = to.replace(/\(v6\)/, '').replace(/\s+on\s+\S+/, '').trim();
  if (/^Anywhere$/i.test(spec)) return true;
  const portPart = spec.split(/\s+/).pop()!;
  const m = /^([\d,:]+)(?:\/(tcp|udp))?$/.exec(portPart);
  if (!m) return false; // application profile names, addresses without ports
  if (m[2] === 'udp') return false;
  return inRange(port, parsePorts(m[1]));
}

export function evaluateUfw(status: UfwStatus, port: number, family: 4 | 6): FirewallVerdict {
  if (!status.active) return { verdict: 'unknown', by: 'ufw inactive' };
  const allowlisted: string[] = [];
  for (const r of status.rules) {
    if (r.v6 !== (family === 6)) continue;
    if (/\bFWD\b|\bOUT\b/.test(r.action)) continue;
    if (!ufwToMatches(r.to, port)) continue;
    const anywhere = /^Anywhere/i.test(r.from);
    const allow = /^(ALLOW|LIMIT)/.test(r.action);
    if (!anywhere) { if (allow) allowlisted.push(r.from); continue; }
    return { verdict: allow ? 'open' : 'blocked', by: `ufw: ${r.to} ${r.action} ${r.from}`, allowlisted: allowlisted.length ? allowlisted : undefined };
  }
  const d = status.defaultIncoming ?? 'allow';
  return { verdict: d === 'deny' || d === 'reject' ? 'blocked' : 'open', by: `ufw default ${d} (incoming)`, allowlisted: allowlisted.length ? allowlisted : undefined };
}

// ─── nft list ruleset (native input chains) ───

export interface NftChain { family: string; table: string; name: string; hook: string; policy: string; rules: string[] }

export function parseNftInputChains(text: string): NftChain[] {
  const out: NftChain[] = [];
  let family = ''; let table = '';
  let cur: NftChain | null = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    const t = /^table\s+(\S+)\s+(\S+)\s*\{/.exec(line);
    if (t) { family = t[1]; table = t[2]; continue; }
    const c = /^chain\s+(\S+)\s*\{/.exec(line);
    if (c) { cur = { family, table, name: c[1], hook: '', policy: 'accept', rules: [] }; continue; }
    if (!cur) continue;
    const h = /type\s+filter\s+hook\s+(\w+)\s+priority\s+[^;]+;\s*(?:policy\s+(\w+);)?/.exec(line);
    if (h) { cur.hook = h[1]; cur.policy = h[2] ?? 'accept'; continue; }
    if (line === '}') {
      if (cur.hook === 'input') out.push(cur);
      cur = null;
      continue;
    }
    if (line) cur.rules.push(line);
  }
  // iptables-nft / ufw tables are evaluated through iptables -S / ufw instead.
  return out.filter((ch) => !((ch.family === 'ip' || ch.family === 'ip6') && ch.table === 'filter'));
}

function nftPortSet(spec: string): PortRange[] {
  return spec.replace(/[{}]/g, '').split(',').map((s) => s.trim()).filter(Boolean).map((p) => {
    const [a, b] = p.split('-');
    return [Number(a), Number(b ?? a)] as PortRange;
  }).filter(([a, b]) => Number.isFinite(a) && Number.isFinite(b));
}

export function evaluateNftChain(chain: NftChain, port: number, family: 4 | 6): FirewallVerdict {
  if ((chain.family === 'ip' && family === 6) || (chain.family === 'ip6' && family === 4)) return { verdict: 'unknown', by: 'other family' };
  const label = `nft ${chain.family} ${chain.table} ${chain.name}`;
  for (const rule of chain.rules) {
    const verdict = /\b(accept|drop|reject)\b\s*(?:with .*)?$/.exec(rule)?.[1];
    if (!verdict) continue;
    if (/\bct state\b/.test(rule) && !/\bnew\b/.test(rule)) continue;
    if (/\biifname\s+"?lo"?/.test(rule)) continue;
    if (/\b(udp|icmp|icmpv6)\b/.test(rule) && !/\btcp\b/.test(rule)) continue;
    const dp = /\btcp dport\s+(\{[^}]*\}|[\d-]+)/.exec(rule) ?? /\bth dport\s+(\{[^}]*\}|[\d-]+)/.exec(rule);
    if (/\bdport\b/.test(rule) && (!dp || !inRange(port, nftPortSet(dp[1])))) continue;
    if (/\b(ip|ip6)\s+saddr\b/.test(rule) && !/saddr\s+!=/.test(rule)) continue; // source-limited
    return { verdict: verdict === 'accept' ? 'open' : 'blocked', by: `${label}: ${rule}` };
  }
  const p = chain.policy.toLowerCase();
  return { verdict: p === 'drop' ? 'blocked' : 'open', by: `${label} policy ${p}` };
}

// ─── boot persistence of DOCKER-USER ───

/** Which of these files would recreate DOCKER-USER rules at boot? */
export function findDockerUserRestore(files: Array<{ path: string; content: string }>): string[] {
  const out: string[] = [];
  for (const f of files) {
    if (/\/rules\.v[46]$/.test(f.path)) {
      if (/^-A DOCKER-USER\s+(?!-j RETURN\s*$)/m.test(f.content)) out.push(f.path);
    } else if (/DOCKER-USER/.test(f.content) && /(-A|-I|--append|--insert|add rule|insert rule)\b/.test(f.content)) {
      out.push(f.path);
    }
  }
  return out;
}

/** ExecStart / ExecStartPre / ExecStartPost scripts named in a unit file. */
export function unitExecPaths(unit: string): string[] {
  const out: string[] = [];
  for (const m of unit.matchAll(/^ExecStart(?:Pre|Post)?=[-@:+!]*(\/\S+)/gm)) out.push(m[1]);
  return out;
}

// ─── assessment (pure) ───

export interface ExposureInput {
  root: boolean;
  exposures: Exposure[];
  publicCount: number;
  mappings: DockerPortMapping[];
  dockerUser: { 4: IptChain | null; 6: IptChain | null };
  hostVerdict: (port: number, family: 4 | 6) => FirewallVerdict;
  /** null when DOCKER-USER is empty or unreadable (no restore needed / unknown). */
  restoreFiles: string[] | null;
}

function describe(e: Exposure): string {
  const where = `${e.family === 6 ? `[${e.addr}]` : e.addr}:${e.hostPort}`;
  if (e.kind === 'docker') {
    const inner = e.containerPort !== undefined && e.containerPort !== e.hostPort ? ` -> container ${e.containerPort}` : '';
    return `${e.service} published by Docker on ${where}${inner}${e.container ? ` (${e.container})` : ''}`;
  }
  return `${e.service} listening on ${where}${e.process ? ` (${e.process}${e.pid ? ` pid ${e.pid}` : ''})` : ''}`;
}

export function assessExposure(input: ExposureInput): CheckItem[] {
  const items: CheckItem[] = [];
  for (const e of input.exposures) {
    const details: Record<string, unknown> = { kind: e.kind, address: e.addr, family: e.family, host_port: e.hostPort, container_port: e.containerPort, container: e.container, process: e.process, service: e.service };
    if (!input.root) {
      items.push({ status: 'warn', message: `${describe(e)}: firewall not readable without root`, details });
      continue;
    }
    let v: FirewallVerdict;
    const chain = e.kind === 'docker' ? input.dockerUser[e.family] : null;
    if (e.kind === 'docker' && chain) {
      v = evaluateIptChain(chain, { dport: e.containerPort ?? e.hostPort, origDport: e.hostPort }, 'open');
      if (v.verdict === 'open') v.by = `DOCKER-USER: ${v.by}; ufw and INPUT do not apply to published ports`;
    } else if (e.kind === 'docker' && e.family === 4) {
      v = { verdict: 'open', by: 'no DOCKER-USER chain; ufw and INPUT do not apply to published ports' };
    } else {
      // Host process, or IPv6 published through docker-proxy (no ip6tables DOCKER-USER): INPUT applies.
      v = input.hostVerdict(e.hostPort, e.family);
    }
    details.firewall = v;
    if (v.verdict === 'blocked') continue;
    const allow = v.allowlisted?.length ? `; allowlisted ${v.allowlisted.join(', ')}` : '';
    if (v.verdict === 'unknown') {
      items.push({ status: 'warn', message: `${describe(e)}: could not tell whether a firewall blocks it (${v.by})`, details });
    } else if (/^ufw: .*ALLOW/.test(v.by)) {
      items.push({ status: 'warn', message: `${describe(e)}: explicitly allowed from anywhere (${v.by})`, details });
    } else {
      items.push({ status: 'fail', message: `${describe(e)} and no firewall rule blocks it (${v.by}${allow})`, details });
    }
  }
  const publishedPublic = input.mappings.some((m) => m.proto === 'tcp' && isWildcard(m.hostIp));
  if (input.root) {
    for (const fam of [4, 6] as const) {
      const chain = input.dockerUser[fam];
      if (!chain) continue;
      if (fam === 4 && publishedPublic && isEmptyDockerUser(chain)) {
        items.push({ status: 'warn', message: 'Docker publishes ports on 0.0.0.0 but the DOCKER-USER chain is empty: nothing filters them, ufw does not apply' });
      }
      const byPort = new Map<number, IneffectiveRule[]>();
      for (const r of findIneffectiveDockerUserRules(chain, input.mappings.filter((m) => m.family === fam))) byPort.set(r.hostPort, [...(byPort.get(r.hostPort) ?? []), r]);
      for (const [hostPort, rules] of byPort) {
        const r = rules[0];
        items.push({
          status: 'warn',
          message: `${rules.length} DOCKER-USER rule(s) on --dport ${hostPort} never match ${r.container}: after DNAT the packet's dport is ${r.containerPort}; use --dport ${r.containerPort} or -m conntrack --ctorigdstport ${hostPort}`,
          details: { rules: rules.map((x) => x.rule), host_port: hostPort, container_port: r.containerPort, container: r.container },
        });
      }
    }
    const live = input.dockerUser[4];
    if (live && !isEmptyDockerUser(live) && input.restoreFiles && input.restoreFiles.length === 0) {
      items.push({ status: 'warn', message: 'DOCKER-USER has live rules but nothing restores them at boot (no systemd unit or script mentioning DOCKER-USER, no -A DOCKER-USER in /etc/iptables/rules.v4): a reboot reopens every port they close' });
    }
  }
  return items;
}

// ─── orchestrator ───

function hasGlobalV6(): boolean {
  const text = sysRead('/proc/net/if_inet6');
  if (!text) return false;
  return text.split('\n').some((l) => {
    const f = l.trim().split(/\s+/);
    return f.length >= 6 && f[3] === '00' && f[5] !== 'lo' && !/^f[cd]/.test(f[0]);
  });
}

function procListeners(): Listener[] {
  const rows = [
    ...parseProcNetTcp(sysRead('/proc/net/tcp') ?? '', 4),
    ...parseProcNetTcp(sysRead('/proc/net/tcp6') ?? '', 6),
  ];
  const byInode = new Map<string, { pid: number; comm: string }>();
  try {
    for (const d of readdirSync('/proc')) {
      if (!/^\d+$/.test(d)) continue;
      let fds: string[] = [];
      try { fds = readdirSync(`/proc/${d}/fd`); } catch { continue; }
      for (const fd of fds) {
        try {
          const m = /^socket:\[(\d+)\]$/.exec(readlinkSync(`/proc/${d}/fd/${fd}`));
          if (m && !byInode.has(m[1])) byInode.set(m[1], { pid: Number(d), comm: sysRead(`/proc/${d}/comm`)?.trim() ?? '' });
        } catch { /* gone */ }
      }
    }
  } catch { /* none */ }
  return rows.map(({ inode, ...l }) => {
    const p = byInode.get(inode);
    return { ...l, process: p?.comm, pid: p?.pid };
  });
}

function readDockerUser(cmd: 'iptables' | 'ip6tables'): IptChain | null {
  if (!sysWhich(cmd)) return null;
  const out = sysRun(cmd, ['-w', '5', '-S', 'DOCKER-USER'], 20_000);
  if (out.code !== 0) return null;
  return parseIptablesChain(out.stdout, 'DOCKER-USER');
}

const RESTORE_DIRS = ['/etc/systemd/system', '/usr/local/sbin', '/usr/local/bin', '/etc/network/if-pre-up.d', '/etc/network/if-up.d', '/etc/NetworkManager/dispatcher.d', '/etc/docker'];
const RESTORE_FILES = ['/etc/iptables/rules.v4', '/etc/iptables/rules.v6', '/etc/sysconfig/iptables', '/etc/rc.local', '/etc/nftables.conf', '/etc/ufw/after.rules', '/etc/ufw/before.rules'];

function collectRestoreCandidates(): Array<{ path: string; content: string }> {
  const files: Array<{ path: string; content: string }> = [];
  const seen = new Set<string>();
  const addFile = (p: string) => {
    if (seen.has(p)) return;
    seen.add(p);
    try { const st = statSync(p); if (!st.isFile() || st.size > 2 * 1024 * 1024) return; } catch { return; }
    const content = sysRead(p);
    if (content !== null) files.push({ path: p, content });
  };
  const walkDir = (dir: string, depth: number) => {
    let entries: string[];
    try { entries = readdirSync(dir); } catch { return; }
    for (const e of entries) {
      const p = `${dir}/${e}`;
      let st;
      try { st = statSync(p); } catch { continue; }
      if (st.isDirectory()) { if (depth < 2) walkDir(p, depth + 1); } else addFile(p);
    }
  };
  for (const d of RESTORE_DIRS) walkDir(d, 0);
  for (const f of RESTORE_FILES) if (existsSync(f)) addFile(f);
  // Scripts that systemd units run, wherever they live.
  for (const f of [...files]) {
    if (f.path.endsWith('.service')) for (const p of unitExecPaths(f.content)) addFile(p);
  }
  return files;
}

export function checkNetworkExposure(ctx: HostContext): Omit<CheckResult, 'id' | 'title'> {
  const ss = sysWhich('ss') ? sysRun('ss', ['-tlnpH'], 30_000) : null;
  const listeners = ss && ss.code === 0 ? parseSsListeners(ss.stdout) : procListeners();

  let mappings: DockerPortMapping[] = [];
  let dockerKnown = false;
  let dockerNote = '';
  if (sysWhich('docker')) {
    const ps = sysRun('docker', ['ps', '--format', '{{.Names}}\t{{.Ports}}'], 60_000);
    if (ps.code === 0) { mappings = parseDockerPsPorts(ps.stdout); dockerKnown = true; } else dockerNote = '; docker ps failed, published container ports unknown';
  }

  const v6 = hasGlobalV6();
  const { sensitive, publicCount } = classifyExposures(listeners, mappings, { hasGlobalV6: v6, dockerKnown });

  const dockerUser = { 4: ctx.root ? readDockerUser('iptables') : null, 6: ctx.root && v6 ? readDockerUser('ip6tables') : null };

  let ufw: UfwStatus | null = null;
  let input: { 4: IptChain | null; 6: IptChain | null } = { 4: null, 6: null };
  let nft: NftChain[] = [];
  if (ctx.root) {
    if (sysWhich('ufw')) {
      const u = sysRun('ufw', ['status', 'verbose'], 20_000);
      if (u.code === 0) ufw = parseUfwStatus(u.stdout);
    }
    for (const [fam, cmd] of [[4, 'iptables'], [6, 'ip6tables']] as const) {
      if (!sysWhich(cmd)) continue;
      const r = sysRun(cmd, ['-w', '5', '-S', 'INPUT'], 20_000);
      if (r.code === 0) input = { ...input, [fam]: parseIptablesChain(r.stdout, 'INPUT') };
    }
    if (sysWhich('nft')) {
      const r = sysRun('nft', ['list', 'ruleset'], 30_000);
      if (r.code === 0) nft = parseNftInputChains(r.stdout);
    }
  }
  const hostVerdict = (port: number, family: 4 | 6): FirewallVerdict => {
    const layers: FirewallVerdict[] = [];
    if (ufw?.active) layers.push(evaluateUfw(ufw, port, family));
    else if (input[family]) layers.push(evaluateIptChain(input[family]!, { dport: port, origDport: port }));
    for (const ch of nft) {
      const v = evaluateNftChain(ch, port, family);
      if (v.verdict !== 'unknown') layers.push(v);
    }
    const blocked = layers.find((l) => l.verdict === 'blocked');
    if (blocked) return blocked;
    if (!layers.length) return { verdict: 'open', by: 'no ufw, INPUT or nftables input filtering found' };
    return { verdict: 'open', by: layers.map((l) => l.by).join('; '), allowlisted: layers.flatMap((l) => l.allowlisted ?? []) };
  };

  const dockerUserLive = dockerUser[4] && !isEmptyDockerUser(dockerUser[4]);
  const restoreFiles = dockerUserLive ? findDockerUserRestore(collectRestoreCandidates()) : null;

  const items = assessExposure({ root: ctx.root, exposures: sensitive, publicCount, mappings, dockerUser, hostVerdict, restoreFiles });
  const fails = items.filter((i) => i.status === 'fail').length;
  const warns = items.filter((i) => i.status === 'warn').length;
  const status: CheckResult['status'] = fails ? 'fail' : warns ? 'warn' : 'pass';
  let reason = fails ? `${fails} sensitive port(s) reachable from the internet${warns ? `, ${warns} warning(s)` : ''}`
    : warns ? `${warns} item(s) to review`
      : `${sensitive.length} sensitive public listener(s), all firewalled; ${publicCount} public TCP listener(s) in all`;
  if (restoreFiles?.length) reason += `; DOCKER-USER restored at boot by ${restoreFiles.slice(0, 3).join(', ')}`;
  reason += dockerNote;
  return { status, reason, items, partial: !ctx.root || (!dockerKnown && !!sysWhich('docker')) };
}
