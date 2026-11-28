import { existsSync } from 'node:fs';
import { request, type ClientRequest, type IncomingMessage } from 'node:http';
import { isIP } from 'node:net';
import type { ThreatEvent } from '../../types/events.js';
import { insertEvent } from '../../core/state.js';
import { DEFAULT_PROTECTED, isProtected } from '../firewall/protected.js';
import { isSuccessfulAuth } from '../firewall/remediation.js';
import { shellLogDetector } from './postgres-shell.js';

/**
 * `[docker_logs]`: tails Docker container logs for Postgres authentication
 * failures (module `postgres-guard`), so `postgres-auth-bruteforce` can ban
 * the source.
 *
 * 2026-11-20, dev2: Supabase Postgres containers had 5432 published on
 * 0.0.0.0. One of them logged ~10,150 `password authentication failed for
 * user "postgres"` lines from ~60 addresses in 72 hours and nothing was
 * banned: the daemon's inputs are log files and journald, and Docker's
 * default json-file driver sends container output to neither. So this follows
 * the containers themselves, over the Engine API on the Docker socket.
 *
 *   [docker_logs]
 *   enabled = true                              # default: on when the socket exists
 *   socket = "/var/run/docker.sock"
 *   name_pattern = "supabase-db$"               # container name (no leading /), regex
 *   image_pattern = "(^|/)postgres(:|@|$)"      # image, regex; either one matching is enough
 *   poll_seconds = 15                           # how soon a new/restarted container is picked up
 *
 * The client address comes from the line itself, so it is only known when
 * `log_line_prefix` includes `%h`/`%r` (Supabase's images put it first), or
 * from a pg_hba reject, which always names the host. Private, loopback and
 * Docker-bridge addresses and the `[remediation] protected` list are never
 * reported as a source: a misconfigured app on the bridge must not get its own
 * network banned.
 *
 * App detections (`app_detections`, on by default): an application that sees
 * an attack the network cannot (a logged-in HTTPS POST carrying an RCE payload
 * in a JSON body, which nginx never logs) prints one line to stdout/stderr:
 *
 *   THREATCRUSH_DETECTION {"v":1,"ip":"…","severity":"high","category":"app.rce_payload","source":"infernet","reason":"…"}
 *
 * and the matching container (`app_name_pattern`, every container by default)
 * becomes an ordinary `app-detection` event with that source address and
 * severity. It goes through the rule engine and remediation like every other
 * detection, so `min_severity`, the strike ladder, `max_ban`, `protected`, the
 * operator's SSH session and dry-run all apply; nothing here touches the
 * firewall. See `parseAppDetection` for what is accepted.
 */
export interface DockerLogsSettings {
  enabled: boolean;
  socket: string;
  namePattern: RegExp;
  imagePattern: RegExp;
  pollMs: number;
  /** Follow `app_name_pattern` containers for `THREATCRUSH_DETECTION` lines. */
  appDetections: boolean;
  /** Which containers are trusted to report attackers. */
  appNamePattern: RegExp;
}

export interface DockerLogsSection {
  enabled?: boolean;
  socket?: string;
  name_pattern?: string;
  image_pattern?: string;
  poll_seconds?: number;
  app_detections?: boolean;
  app_name_pattern?: string;
}

export const DEFAULT_DOCKER_SOCKET = '/var/run/docker.sock';
export const DEFAULT_NAME_PATTERN = 'supabase-db$';
/** `postgres`, `supabase/postgres:15.8`, `postgres@sha256:…`; not `postgrest/postgrest`. */
export const DEFAULT_IMAGE_PATTERN = '(^|/)postgres(:|@|$)';
/** Every container may report app detections unless the operator narrows it. */
export const DEFAULT_APP_NAME_PATTERN = '.*';

function regexOr(source: unknown, fallback: string): RegExp {
  if (typeof source === 'string' && source) {
    try { return new RegExp(source, 'i'); } catch { /* fall back */ }
  }
  return new RegExp(fallback, 'i');
}

export function dockerLogsSettings(section?: DockerLogsSection): DockerLogsSettings {
  const poll = Number(section?.poll_seconds);
  return {
    enabled: section?.enabled !== false,
    socket: typeof section?.socket === 'string' && section.socket ? section.socket : DEFAULT_DOCKER_SOCKET,
    namePattern: regexOr(section?.name_pattern, DEFAULT_NAME_PATTERN),
    imagePattern: regexOr(section?.image_pattern, DEFAULT_IMAGE_PATTERN),
    pollMs: Number.isFinite(poll) && poll >= 2 ? poll * 1000 : 15_000,
    appDetections: section?.app_detections !== false,
    appNamePattern: regexOr(section?.app_name_pattern, DEFAULT_APP_NAME_PATTERN),
  };
}

// ─── Postgres line parsing ───────────────────────────────────────────────────

export interface PostgresAuthFailure {
  kind: 'password' | 'pg_hba';
  ip?: string;
  user?: string;
  database?: string;
}

const PASSWORD_FAILED = /FATAL:\s+password authentication failed for user "([^"]*)"/;
const HBA_REJECT = /FATAL:\s+no pg_hba\.conf entry for (?:replication connection from )?host "([^"]+)", user "([^"]*)"(?:, database "([^"]*)")?/;

/** A bare address from what Postgres prints for `%h`/`%r`: `1.2.3.4`, `1.2.3.4(5432)`, `::ffff:1.2.3.4`, `[::1]`. */
export function cleanPgHost(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  let host = raw.trim().replace(/\(\d+\)$/, '').replace(/^\[|\]$/g, '');
  if (/^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(host)) host = host.slice(7);
  return isIP(host) ? host : undefined;
}

/**
 * The client address a Postgres log line was written for: the first token when
 * `log_line_prefix` starts with `%h`/`%r` (Supabase's do), or a `host=`/
 * `client=` field anywhere in the prefix.
 */
function prefixHost(line: string): string | undefined {
  const first = cleanPgHost(line.split(/\s/, 1)[0]);
  if (first) return first;
  const m = /\b(?:host|client|remote)=(\S+?)[\s,]/.exec(line);
  return cleanPgHost(m?.[1]);
}

/** A failed Postgres authentication, or null for any other line. */
export function parsePostgresAuthFailure(line: string): PostgresAuthFailure | null {
  const hba = HBA_REJECT.exec(line);
  if (hba) {
    return {
      kind: 'pg_hba',
      ip: cleanPgHost(hba[1]) ?? prefixHost(line),
      user: hba[2],
      ...(hba[3] !== undefined ? { database: hba[3] } : {}),
    };
  }
  const pw = PASSWORD_FAILED.exec(line);
  if (pw) {
    const ip = prefixHost(line);
    // `%u@%d` in the prefix ("postgres@postgres FATAL: …") names the database.
    const db = /\s([^\s@]+)@([^\s@]+)\s+FATAL:/.exec(line);
    return { kind: 'password', ...(ip ? { ip } : {}), user: pw[1], ...(db ? { database: db[2] } : {}) };
  }
  return null;
}

/** Never a ban target: private, loopback, link-local, Docker bridges, and the operator's protected list. */
export function isUnbannableSource(ip: string, protectedList: string[] = []): boolean {
  return isProtected(ip, [...DEFAULT_PROTECTED, ...protectedList]);
}

/**
 * The `postgres-guard` event for one container log line, or null when it is
 * not an auth failure, names no client, or the client may never be banned.
 */
export function postgresAuthEvent(
  line: string,
  container: string,
  protectedList: string[] = [],
  now: Date = new Date(),
): ThreatEvent | null {
  const failure = parsePostgresAuthFailure(line);
  if (!failure?.ip) return null;
  if (isUnbannableSource(failure.ip, protectedList)) return null;
  const who = `user "${failure.user ?? ''}"${failure.database !== undefined ? ` database "${failure.database}"` : ''}`;
  const message = failure.kind === 'password'
    ? `Postgres password authentication failed for ${who} from ${failure.ip} (${container})`
    : `Postgres connection rejected by pg_hba for ${who} from ${failure.ip} (${container})`;
  return {
    timestamp: now,
    module: 'postgres-guard',
    category: 'auth',
    // One failure is not an attack, and anything at the remediation floor
    // (`min_severity`, high by default) bans on its own. The rule decides.
    severity: 'low',
    message,
    source_ip: failure.ip,
    details: {
      service: 'postgres',
      container,
      kind: failure.kind,
      ...(failure.user !== undefined ? { user: failure.user } : {}),
      ...(failure.database !== undefined ? { database: failure.database } : {}),
      line: line.slice(0, 500),
    },
  };
}

// ─── App detections (THREATCRUSH_DETECTION) ─────────────────────────────────

export const APP_DETECTION_MARKER = 'THREATCRUSH_DETECTION ';
/** A detection line longer than this is ignored, not truncated. */
export const APP_DETECTION_MAX_LINE = 4096;
/**
 * At most this much may precede the marker: a console timestamp or a
 * `[app]` tag. A marker deeper in the line is more likely user input an app
 * echoed into its log than the app's own report.
 */
const APP_DETECTION_MAX_PREFIX = 80;
const APP_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
/** Never a real client: unspecified, multicast and reserved. */
const NOT_A_CLIENT = ['0.0.0.0/8', '224.0.0.0/4', '240.0.0.0/4', '::/128', 'ff00::/8'];

export interface AppDetection {
  ip: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Always `app.<name>`. */
  category: string;
  source?: string;
  reason?: string;
  account?: string;
}

/** Control characters out, whitespace collapsed, capped; undefined when nothing is left. */
function cleanText(value: unknown, max: number): string | undefined {
  if (typeof value !== 'string') return undefined;
  // eslint-disable-next-line no-control-regex
  const text = value.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ').replace(/\s+/g, ' ').trim();
  return text ? text.slice(0, max) : undefined;
}

/** `rce_payload`, `app.rce_payload`, `App.RCE Payload` → `app.rce_payload`. */
function appCategory(value: unknown): string | undefined {
  const text = cleanText(value, 64)?.toLowerCase().replace(/^app\./, '').replace(/[^a-z0-9._-]+/g, '_').replace(/^[._-]+|[._-]+$/g, '');
  return text ? `app.${text}`.slice(0, 64) : undefined;
}

/** `1.2.3.4`, `::ffff:1.2.3.4`, `[2001:db8::1]` → a bare address, or undefined. */
function cleanIp(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  let ip = value.trim().replace(/^\[|\]$/g, '');
  if (/^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(ip)) ip = ip.slice(7);
  return isIP(ip) ? ip : undefined;
}

/**
 * The detection on one log line, or null. Accepted: the marker at the start of
 * the line or after a short prefix (no quotes or braces), then one JSON object
 * and nothing else, `v` 1, a valid IP, a known severity and a category. Any
 * line over 4 KB, any malformed JSON, any other version is ignored.
 * Whether the address may be banned is decided by the caller.
 */
export function parseAppDetection(line: string): AppDetection | null {
  if (line.length > APP_DETECTION_MAX_LINE) return null;
  const at = line.indexOf(APP_DETECTION_MARKER);
  if (at < 0 || at > APP_DETECTION_MAX_PREFIX) return null;
  if (/["'{}]/.test(line.slice(0, at))) return null;
  let doc: unknown;
  try { doc = JSON.parse(line.slice(at + APP_DETECTION_MARKER.length)); } catch { return null; }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return null;
  const d = doc as Record<string, unknown>;
  if (d.v !== 1) return null;
  const ip = cleanIp(d.ip);
  if (!ip) return null;
  if (typeof d.severity !== 'string' || !APP_SEVERITIES.has(d.severity)) return null;
  const category = appCategory(d.category);
  if (!category) return null;
  const source = cleanText(d.source, 64);
  const reason = cleanText(d.reason, 300);
  const account = cleanText(d.account, 128);
  return {
    ip,
    severity: d.severity as AppDetection['severity'],
    category,
    ...(source ? { source } : {}),
    ...(reason ? { reason } : {}),
    ...(account ? { account } : {}),
  };
}

/**
 * The `app-detection` event for one container log line, or null when the line
 * is not a valid detection or its address may never be banned (private,
 * loopback, link-local, Docker bridge, CGNAT, the protected list, or whatever
 * `isProtected` says: the live remediation allowlist, which includes the
 * operator's SSH session).
 *
 * The category is `web`: the app saw the request, so the handshake completed
 * and the source is not spoofed (the abuse-reporter's bar), and it maps to
 * AbuseIPDB 21 (Web App Attack). The app's own category is `details.app_category`.
 */
export function appDetectionEvent(
  line: string,
  container: string,
  protectedList: string[] = [],
  isProtectedNow?: (ip: string) => boolean,
  now: Date = new Date(),
): ThreatEvent | null {
  const d = parseAppDetection(line);
  if (!d) return null;
  if (isUnbannableSource(d.ip, [...NOT_A_CLIENT, ...protectedList])) return null;
  if (isProtectedNow?.(d.ip)) return null;
  const source = d.source ?? container;
  // The reason may quote attacker input (a field name); it must never read as
  // a successful login, which remediation declines to ban.
  const reason = d.reason && !isSuccessfulAuth(d.reason) ? `: ${d.reason}` : '';
  return {
    timestamp: now,
    module: 'app-detection',
    category: 'web',
    severity: d.severity,
    message: `${source} reported ${d.category} from ${d.ip} (${container})${reason}`,
    source_ip: d.ip,
    details: {
      app_category: d.category,
      source,
      container,
      ...(d.reason ? { reason: d.reason } : {}),
      ...(d.account ? { account: d.account } : {}),
    },
  };
}

// ─── Docker log stream framing ───────────────────────────────────────────────

/**
 * Splits a container log stream into lines. Without a TTY, Docker multiplexes
 * stdout and stderr into frames: 1 byte stream, 3 zero bytes, a 4-byte
 * big-endian length, then the payload. With a TTY the stream is raw text.
 */
export class DockerLogDecoder {
  private pending: Buffer = Buffer.alloc(0);
  private partial = new Map<number, string>();

  constructor(private tty: boolean, private onLine: (line: string) => void) {}

  push(chunk: Buffer): void {
    if (this.tty) {
      this.text(1, chunk.toString('utf-8'));
      return;
    }
    this.pending = this.pending.length ? Buffer.concat([this.pending, chunk]) : chunk;
    while (this.pending.length >= 8) {
      const stream = this.pending[0];
      const size = this.pending.readUInt32BE(4);
      if (stream > 2 || this.pending[1] !== 0 || this.pending[2] !== 0 || this.pending[3] !== 0) {
        // Not framed after all (a TTY we were not told about): read it raw.
        this.tty = true;
        const rest = this.pending;
        this.pending = Buffer.alloc(0);
        this.text(1, rest.toString('utf-8'));
        return;
      }
      if (this.pending.length < 8 + size) break;
      this.text(stream, this.pending.subarray(8, 8 + size).toString('utf-8'));
      this.pending = this.pending.subarray(8 + size);
    }
  }

  private text(stream: number, text: string): void {
    let buf = (this.partial.get(stream) ?? '') + text;
    let idx: number;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).replace(/\r$/, '');
      buf = buf.slice(idx + 1);
      if (line) this.onLine(line);
    }
    // A line that never ends is not a log line worth holding forever.
    this.partial.set(stream, buf.length > 65_536 ? '' : buf);
  }
}

// ─── The watcher ─────────────────────────────────────────────────────────────

interface ContainerSummary { Id: string; Names?: string[]; Image?: string; State?: string }

/** What a container is followed for: Postgres auth lines, app detections, or both. */
export interface FollowRoles { postgres: boolean; app: boolean }

interface Follow { req: ClientRequest; name: string; roles: FollowRoles }

export interface DockerLogsDeps {
  /** GET a JSON document from the Engine API. */
  getJson(path: string): Promise<unknown>;
  /** Open a streaming GET; `onData` per chunk, `onEnd` once when it closes for any reason. */
  stream(path: string, onData: (chunk: Buffer) => void, onEnd: () => void): ClientRequest;
}

function socketDeps(socketPath: string): DockerLogsDeps {
  return {
    getJson: (path) => new Promise((resolve, reject) => {
      const req = request({ socketPath, path, method: 'GET', timeout: 10_000 }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf-8');
          if ((res.statusCode ?? 500) >= 300) return reject(new Error(`docker ${path}: HTTP ${res.statusCode} ${body.slice(0, 200)}`));
          try { resolve(JSON.parse(body)); } catch (err) { reject(err as Error); }
        });
        res.on('error', reject);
      });
      req.on('timeout', () => req.destroy(new Error(`docker ${path}: timed out`)));
      req.on('error', reject);
      req.end();
    }),
    stream: (path, onData, onEnd) => {
      let ended = false;
      const end = () => { if (!ended) { ended = true; onEnd(); } };
      const req = request({ socketPath, path, method: 'GET' }, (res: IncomingMessage) => {
        if ((res.statusCode ?? 500) >= 300) { res.resume(); end(); return; }
        res.on('data', onData);
        res.on('end', end);
        res.on('close', end);
        res.on('error', end);
      });
      req.on('error', end);
      req.on('close', end);
      req.end();
      return req;
    },
  };
}

export class DockerLogsWatch {
  private follows = new Map<string, Follow>();
  /** When each container's stream last closed: a restart resumes from there. */
  private closedAt = new Map<string, number>();
  private timer: NodeJS.Timeout | null = null;
  private lastPoll = 0;
  private stopped = false;
  private deps: DockerLogsDeps;
  private warned = false;
  /** `postgres-shell` signals in the same lines: COPY … PROGRAM, shell errors (cooldown per container). */
  private shellLine = shellLogDetector();

  constructor(private opts: {
    bus: { publish(event: ThreatEvent): void };
    settings: DockerLogsSettings;
    protectedList?: string[];
    /** Live never-ban check (remediation's allowlist, the operator's SSH session included). */
    isProtected?: (ip: string) => boolean;
    log: (line: string) => void;
    deps?: DockerLogsDeps;
  }) {
    this.deps = opts.deps ?? socketDeps(opts.settings.socket);
  }

  /** False when off or there is no Docker here. */
  start(): boolean {
    const { settings } = this.opts;
    if (!settings.enabled) return false;
    if (!this.opts.deps && !existsSync(settings.socket)) return false;
    this.opts.log(`[docker-logs] following containers named /${settings.namePattern.source}/ or with image /${settings.imagePattern.source}/ for Postgres auth failures`);
    if (settings.appDetections) {
      this.opts.log(`[docker-logs] containers named /${settings.appNamePattern.source}/ may report attackers with THREATCRUSH_DETECTION lines`);
    }
    void this.poll();
    this.timer = setInterval(() => { void this.poll(); }, settings.pollMs);
    this.timer.unref?.();
    return true;
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    for (const f of this.follows.values()) { try { f.req.destroy(); } catch { /* closing */ } }
    this.follows.clear();
  }

  /** Names of the containers being followed now. */
  following(): string[] {
    return [...this.follows.values()].map((f) => f.name).sort();
  }

  /** What to follow `c` for; neither role means it is not followed. */
  roles(c: ContainerSummary): FollowRoles {
    const { settings } = this.opts;
    const name = (c.Names?.[0] ?? '').replace(/^\//, '');
    return {
      postgres: settings.namePattern.test(name) || settings.imagePattern.test(c.Image ?? ''),
      app: settings.appDetections && settings.appNamePattern.test(name),
    };
  }

  matches(c: ContainerSummary): boolean {
    const r = this.roles(c);
    return r.postgres || r.app;
  }

  /** One discovery pass: follow new or restarted matches, drop gone ones. */
  async poll(): Promise<void> {
    if (this.stopped) return;
    const now = Date.now();
    const previous = this.lastPoll;
    let list: ContainerSummary[];
    try {
      list = (await this.deps.getJson('/containers/json')) as ContainerSummary[];
      this.warned = false;
    } catch (err) {
      if (!this.warned) this.opts.log(`[docker-logs] cannot list containers: ${(err as Error).message}`);
      this.warned = true;
      return;
    }
    this.lastPoll = now;
    const running = new Set<string>();
    for (const c of Array.isArray(list) ? list : []) {
      if (!c?.Id) continue;
      const roles = this.roles(c);
      if (!roles.postgres && !roles.app) continue;
      running.add(c.Id);
      if (this.follows.has(c.Id)) continue;
      // Resume where the last stream stopped (a restart), or from the previous
      // pass (a container that appeared since); the first pass starts at now.
      const from = this.closedAt.get(c.Id) ?? (previous || now);
      await this.follow(c, from, roles);
    }
    for (const [id, f] of this.follows) {
      if (!running.has(id)) { try { f.req.destroy(); } catch { /* closing */ } this.follows.delete(id); }
    }
    for (const id of this.closedAt.keys()) if (!running.has(id)) this.closedAt.delete(id);
  }

  private async follow(c: ContainerSummary, fromMs: number, roles: FollowRoles): Promise<void> {
    const name = (c.Names?.[0] ?? c.Id.slice(0, 12)).replace(/^\//, '');
    let tty = false;
    try {
      const info = (await this.deps.getJson(`/containers/${c.Id}/json`)) as { Config?: { Tty?: boolean } };
      tty = info?.Config?.Tty === true;
    } catch { /* framed is the common case; the decoder notices otherwise */ }
    if (this.stopped || this.follows.has(c.Id)) return;
    const since = Math.max(1, Math.floor(fromMs / 1000));
    const decoder = new DockerLogDecoder(tty, (line) => this.line(line, name, roles));
    const req = this.deps.stream(
      `/containers/${c.Id}/logs?follow=1&stdout=1&stderr=1&since=${since}`,
      (chunk) => { try { decoder.push(chunk); } catch { /* one bad chunk must not stop the rest */ } },
      () => {
        if (this.follows.get(c.Id)?.req === req) {
          this.follows.delete(c.Id);
          this.closedAt.set(c.Id, Date.now());
        }
      },
    );
    this.follows.set(c.Id, { req, name, roles });
    // One line per container would be ~100 lines at start on a busy host when
    // every container may report app detections; name only the Postgres ones.
    if (roles.postgres) this.opts.log(`[docker-logs] following ${name}`);
  }

  /**
   * Exposed for tests and `rules test`: one container log line through the
   * parsers. Without `roles`, a container is a Postgres one, and may report app
   * detections when its name matches `app_name_pattern`.
   */
  line(line: string, container: string, roles?: FollowRoles): ThreatEvent | null {
    const { settings } = this.opts;
    const r = roles ?? { postgres: true, app: settings.appDetections && settings.appNamePattern.test(container) };
    let event: ThreatEvent | null = null;
    if (r.app && line.includes(APP_DETECTION_MARKER)) {
      event = appDetectionEvent(line, container, this.opts.protectedList ?? [], this.opts.isProtected);
    } else if (r.postgres) {
      event = postgresAuthEvent(line, container, this.opts.protectedList ?? [])
        ?? this.shellLine(line, container);
    }
    if (!event) return null;
    try { insertEvent(event); } catch { /* db optional */ }
    this.opts.bus.publish(event);
    return event;
  }
}
