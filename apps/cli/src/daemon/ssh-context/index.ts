import { hostname } from 'node:os';
import { join } from 'node:path';
import { computeVerdict, type SshLoginContext } from '@threatcrush/event-detail';
import type { ThreatEvent } from '../../types/events.js';
import type { SshContextSection } from '../../types/config.js';
import { SshAuthHistory, type SshdLineLike } from './auth-history.js';
import { AuthorizedKeysIndex } from './authorized-keys.js';
import { classifyAddress, GitHubActionsRanges, NetLookup, normalizeIp, ownAddresses, rangesDeps, type Classifier } from './ip-intel.js';
import { findCiDeploy, type JournalRunner } from './ci-deploy.js';

export { SshAuthHistory } from './auth-history.js';

/**
 * Builds `details.ssh_context` for every accepted SSH login before the rule
 * engine sees it, so the detection that pages (and the dashboard and desktop
 * rows) says who, with which key and options, from where, after what, what
 * the session ran, and a verdict. See @threatcrush/event-detail for the
 * schema and the verdict rules.
 *
 * Bounded: the whole thing waits at most `settle_ms` (+ lookup timeouts) and
 * then sends what it has.
 */

export interface SshContextSettings {
  enabled: boolean;
  networkLookups: boolean;
  githubRanges: boolean;
  expectedKeys: Set<string>;
  ciDeployTag: string;
  failureWindowS: number;
  settleMs: number;
}

export function sshContextSettings(s?: SshContextSection): SshContextSettings {
  const settle = Number(s?.settle_ms);
  const win = Number(s?.failure_window_seconds);
  return {
    enabled: s?.enabled !== false,
    networkLookups: s?.network_lookups !== false,
    githubRanges: s?.github_actions_ranges !== false,
    expectedKeys: new Set((Array.isArray(s?.expected_keys) ? s.expected_keys : []).map(String).filter((k) => k.startsWith('SHA256:'))),
    ciDeployTag: typeof s?.ci_deploy_tag === 'string' && /^[\w.-]{1,64}$/.test(s.ci_deploy_tag) ? s.ci_deploy_tag : 'ci-deploy',
    failureWindowS: Number.isFinite(win) && win >= 60 && win <= 86_400 ? win : 600,
    settleMs: Number.isFinite(settle) && settle >= 0 ? Math.min(settle, 20_000) : 5_000,
  };
}

export interface SshContextDeps {
  history?: SshAuthHistory;
  keys?: Pick<AuthorizedKeysIndex, 'lookup'>;
  ranges?: Pick<GitHubActionsRanges, 'has' | 'refresh'>;
  net?: Pick<NetLookup, 'lookup'>;
  journal?: JournalRunner;
  own?: () => ReadonlySet<string>;
  host?: string;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

/** Whether a bus event is an accepted SSH login this enricher should describe. */
export function isAcceptedLogin(event: ThreatEvent): boolean {
  return event.module === 'ssh-guard' && /SSH login accepted/.test(event.message) && !!event.source_ip;
}

export class SshLoginEnricher {
  readonly history: SshAuthHistory;
  private readonly keys: Pick<AuthorizedKeysIndex, 'lookup'>;
  private readonly ranges: Pick<GitHubActionsRanges, 'has' | 'refresh'>;
  private readonly net: Pick<NetLookup, 'lookup'>;
  private readonly classifier: Classifier;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly host: string;
  private ownCache: { at: number; v: ReadonlySet<string> } = { at: -Infinity, v: new Set() };

  constructor(readonly settings: SshContextSettings, private readonly deps: SshContextDeps & { stateDir?: string } = {}) {
    const now = deps.now ?? Date.now;
    this.history = deps.history ?? new SshAuthHistory(now);
    this.keys = deps.keys ?? new AuthorizedKeysIndex();
    this.ranges = deps.ranges ?? new GitHubActionsRanges(rangesDeps(join(deps.stateDir ?? '.', 'github-actions-ranges.json')), settings.githubRanges);
    this.net = deps.net ?? new NetLookup();
    this.sleep = deps.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.host = deps.host ?? hostname();
    const own = deps.own ?? (() => {
      if (now() - this.ownCache.at > 60_000) this.ownCache = { at: now(), v: ownAddresses() };
      return this.ownCache.v;
    });
    this.classifier = { own, isGitHubActions: (ip) => this.ranges.has(ip) };
  }

  /** Warm the GitHub ranges at start-up; safe to call any time. */
  start(): void {
    if (this.settings.enabled) void this.ranges.refresh();
  }

  recordSshd(line: SshdLineLike): void {
    if (this.settings.enabled) this.history.record(line);
  }

  wants(event: ThreatEvent): boolean {
    return this.settings.enabled && isAcceptedLogin(event) && !('ssh_context' in (event.details ?? {}));
  }

  /** Adds `details.ssh_context` to the event in place and returns it. Never throws. */
  async enrich(event: ThreatEvent): Promise<SshLoginContext | null> {
    try {
      const d = (event.details ??= {}) as Record<string, unknown>;
      const ip = normalizeIp(event.source_ip ?? '');
      const atMs = event.timestamp instanceof Date ? event.timestamp.getTime() : Date.now();
      const user = typeof d.ssh_user === 'string' ? d.ssh_user : /SSH login accepted for (\S+)/.exec(event.message)?.[1];
      const method = typeof d.auth_method === 'string' ? d.auth_method : undefined;
      const fp = typeof d.fingerprint === 'string' && d.fingerprint.startsWith('SHA256:') ? d.fingerprint : undefined;
      const port = typeof d.port === 'number' ? d.port : Number(d.port) || undefined;

      await this.ranges.refresh();
      const kind = classifyAddress(ip, this.classifier);
      const key = fp ? this.keys.lookup(fp, this.settings.expectedKeys) : undefined;
      if (key && !key.type && typeof d.key_type === 'string') key.type = d.key_type;
      const failures = this.history.failuresBefore(atMs, ip, this.settings.failureWindowS);

      const netP = this.settings.networkLookups && (kind === 'public' || kind === 'github-actions')
        ? this.net.lookup(ip).catch(() => null)
        : Promise.resolve(null);
      // Give the forced command time to log its line and a short session time to close.
      const settle = this.sleep(this.settings.settleMs);
      const [net] = await Promise.all([netP, settle]);
      const ci = key?.command ? await findCiDeploy(ip, atMs, this.settings.ciDeployTag, this.deps.journal).catch(() => null) : null;
      const closed = this.history.closeOf(ip, port, atMs);
      let tz: string | undefined;
      try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch { tz = undefined; }

      const base: Omit<SshLoginContext, 'verdict'> = {
        v: 1,
        at: new Date(atMs).toISOString(),
        host: this.host,
        tz_offset_min: -new Date(atMs).getTimezoneOffset(),
        ...(tz ? { tz } : {}),
        ...(user ? { user } : {}),
        ...(method ? { auth_method: method } : {}),
        ...(port ? { port } : {}),
        ...(key ? { key } : {}),
        source: { ip, kind, ...(net ?? {}) },
        failures,
        session: {
          ...(ci ? { ci_deploy: ci } : {}),
          ...(closed !== null ? { closed_at: new Date(closed).toISOString(), duration_s: Math.max(0, Math.round((closed - atMs) / 1000)) } : { open: true }),
        },
      };
      const ctx: SshLoginContext = { ...base, verdict: computeVerdict(base) };
      d.ssh_context = ctx;
      return ctx;
    } catch {
      return null;
    }
  }
}
