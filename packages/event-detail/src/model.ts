import type { EventLike, Severity, SshLoginContext, SourceContext, Verdict } from './types';
import { describeFailures, shortCommand, severityRank } from './verdict';

type Obj = Record<string, unknown>;

function obj(v: unknown): Obj | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : null;
}

function str(v: unknown): string | null {
  return typeof v === 'string' && v.trim() ? v.trim() : typeof v === 'number' ? String(v) : null;
}

/** The evidence object: `metadata.evidence` (rule-engine detection) or the metadata itself (a raw event). */
export function evidenceOf(e: EventLike): Obj {
  const m = obj(e.metadata) ?? {};
  return obj(m.evidence) ?? m;
}

/** The agent's SSH login context, wherever this event carries it; null for older agents and non-SSH events. */
export function sshContextOf(e: EventLike): SshLoginContext | null {
  const m = obj(e.metadata) ?? {};
  const ev = obj(m.evidence);
  const ctx = obj(ev?.ssh_context) ?? obj(m.ssh_context);
  if (!ctx || ctx.v !== 1 || !obj(ctx.verdict)) return null;
  return ctx as unknown as SshLoginContext;
}

export function fingerprintOf(e: EventLike): string | null {
  const ctx = sshContextOf(e);
  const ev = evidenceOf(e);
  const m = obj(e.metadata) ?? {};
  for (const v of [ctx?.key?.fingerprint, ev.fingerprint, m.fingerprint]) {
    const s = str(v);
    if (s && /^SHA256:/.test(s)) return s;
  }
  return null;
}

export function sourceIpOf(e: EventLike): string | null {
  const ev = evidenceOf(e);
  const m = obj(e.metadata) ?? {};
  return str(e.source_ip) ?? str(ev.source_ip) ?? str(m.login_ip) ?? sshContextOf(e)?.source?.ip ?? null;
}

export function hostKeyOf(e: EventLike): string | null {
  return str(e.server_id) ?? str(e.host);
}

export function ruleOf(e: EventLike): string | null {
  const m = obj(e.metadata) ?? {};
  return str(e.rule_id) ?? str(m.rule_id) ?? str(e.module);
}

export function userOf(e: EventLike): string | null {
  const ctx = sshContextOf(e);
  const ev = evidenceOf(e);
  return ctx?.user ?? str(e.username) ?? str(ev.ssh_user) ?? str(ev.user) ?? str(ev.username) ?? str(ev.account) ?? null;
}

/** The severity to show: the agent's verdict for an SSH login (it knows the key and the address), else the event's own. */
export function effectiveSeverity(e: EventLike): Severity {
  const ctx = sshContextOf(e);
  if (ctx) return ctx.verdict.severity;
  const s = (e.severity ?? 'info') as Severity;
  return (['info', 'low', 'medium', 'high', 'critical'] as const).includes(s) ? s : 'info';
}

export function sourceLabel(s: SourceContext | undefined | null): string | null {
  if (!s) return null;
  switch (s.kind) {
    case 'github-actions': return ['GitHub Actions', s.as_org ? `${s.as_org}${s.asn ? ` AS${s.asn}` : ''}` : null, s.country].filter(Boolean).join(', ');
    case 'tailscale': return 'Tailscale (100.64.0.0/10)';
    case 'self': return "this host's own address";
    case 'loopback': return 'loopback';
    case 'private': return 'private network';
    default: {
      const parts = [s.as_org ? `${s.as_org}${s.asn ? ` AS${s.asn}` : ''}` : s.asn ? `AS${s.asn}` : null, s.country, s.rdns].filter(Boolean);
      return parts.length ? parts.join(', ') : 'public address';
    }
  }
}

function keyLabel(ctx: SshLoginContext): string | null {
  const k = ctx.key;
  if (!k) return null;
  const name = k.comment ? `"${k.comment}"` : k.fingerprint ? k.fingerprint.slice(0, 19) + '…' : null;
  const kind = k.command ? 'forced-command key' : k.found ? (k.from || k.restrict ? 'restricted key' : 'unrestricted key') : 'key (not found on host)';
  return [kindLabel(k.type), kind, name].filter(Boolean).join(' ');
}

function kindLabel(type: string | undefined): string | null {
  if (!type) return null;
  const t = type.replace(/^ssh-/, '').replace(/^ecdsa-sha2-/, 'ECDSA-').replace(/@openssh\.com$/, '');
  return t.toUpperCase().startsWith('ED25519') ? 'ED25519' : t.toUpperCase();
}

export interface RowSummary {
  /** One line for a list row. */
  text: string;
  verdict: Verdict | null;
}

/**
 * The list row: the alert's title plus who, how, from where and the verdict,
 * so a CI deploy reads as one in the row itself.
 */
export function rowSummary(e: EventLike): RowSummary {
  const title = str(e.title) ?? str(e.message) ?? ruleOf(e) ?? 'event';
  const ctx = sshContextOf(e);
  if (!ctx) {
    const user = userOf(e);
    const ev = evidenceOf(e);
    const comment = str(ev.key_comment);
    const extra = [user ? `user ${user}` : null, str(ev.auth_method), comment ? `key "${comment}"` : null].filter(Boolean).join(' · ');
    return { text: extra && !title.includes(extra) ? `${title} · ${extra}` : title, verdict: null };
  }
  const who = ctx.user ? `${ctx.user}${ctx.host ? `@${ctx.host}` : ''}` : ctx.host ?? null;
  const how = [ctx.auth_method, keyLabel(ctx)].filter(Boolean).join(' ');
  const src = ctx.source ? `from ${ctx.source.ip}${sourceLabel(ctx.source) ? ` (${sourceLabel(ctx.source)})` : ''}` : null;
  return { text: [title, who, how, src].filter(Boolean).join(' · '), verdict: ctx.verdict };
}

export interface DetailRow {
  label: string;
  value: string;
  mono?: boolean;
  tone?: 'bad' | 'warn' | 'good' | 'dim';
}

export interface DetailSection {
  id: string;
  title: string;
  rows: DetailRow[];
  note?: string;
}

export interface DetailModel {
  title: string;
  severity: Severity;
  /** The severity the event was raised with, when the verdict changed it. */
  raisedSeverity: Severity | null;
  verdict: Verdict | null;
  headline: string;
  sections: DetailSection[];
  /** What the timeline relates on. */
  keys: { ip: string | null; fingerprint: string | null; host: string | null; rule: string | null };
}

const pad = (n: number) => String(Math.abs(n)).padStart(2, '0');

export function toMs(at: string | number): number {
  return typeof at === 'number' ? at : Date.parse(at);
}

export function utcString(ms: number): string {
  return Number.isNaN(ms) ? 'unknown' : new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

/** The time on the host's own clock, from its UTC offset. */
export function hostLocalString(ms: number, offsetMin: number | undefined, tz?: string): string | null {
  if (offsetMin === undefined || Number.isNaN(ms)) return null;
  const d = new Date(ms + offsetMin * 60_000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
  const sign = offsetMin >= 0 ? '+' : '-';
  return `${d} (UTC${sign}${pad(Math.trunc(offsetMin / 60))}:${pad(offsetMin % 60)}${tz ? ` ${tz}` : ''})`;
}

function duration(s: number): string {
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

const VERDICT_TONE: Record<string, DetailRow['tone']> = {
  expected: 'good', 'likely-ci': 'good', internal: 'good', review: 'warn', suspicious: 'bad',
};

/** Everything the detail view shows, as labelled rows. Only facts the event carries; nothing is guessed. */
export function detailModel(e: EventLike, opts: { originLabel?: string | null; viewerTime?: (ms: number) => string } = {}): DetailModel {
  const ctx = sshContextOf(e);
  const ev = evidenceOf(e);
  const ms = toMs(ctx?.at ?? e.at);
  const severity = effectiveSeverity(e);
  const raised = (e.severity ?? null) as Severity | null;
  const sections: DetailSection[] = [];
  const keys = { ip: sourceIpOf(e), fingerprint: fingerprintOf(e), host: hostKeyOf(e), rule: ruleOf(e) };

  const when: DetailRow[] = [];
  const host = ctx?.host ?? str(e.host);
  if (host) when.push({ label: 'Host', value: host, mono: true });
  const hostLocal = hostLocalString(ms, ctx?.tz_offset_min, ctx?.tz);
  if (hostLocal) when.push({ label: 'Host local time', value: hostLocal, mono: true });
  when.push({ label: 'UTC', value: utcString(ms), mono: true });
  if (opts.viewerTime && !Number.isNaN(ms)) when.push({ label: 'Your time', value: opts.viewerTime(ms), tone: 'dim' });
  if (e.occurrences && e.occurrences > 1) when.push({ label: 'Occurrences', value: String(e.occurrences) });
  sections.push({ id: 'when', title: 'When and where', rows: when });

  const login: DetailRow[] = [];
  const user = userOf(e);
  if (user) login.push({ label: 'Target user', value: user, mono: true, tone: user === 'root' ? 'warn' : undefined });
  const method = ctx?.auth_method ?? str(ev.auth_method);
  if (method) login.push({ label: 'Auth method', value: method, tone: method === 'password' ? 'warn' : undefined });
  const k = ctx?.key;
  const keyType = k?.type ?? str(ev.key_type);
  if (keyType) login.push({ label: 'Key type', value: keyType, mono: true });
  if (keys.fingerprint) login.push({ label: 'Fingerprint', value: keys.fingerprint, mono: true });
  const comment = k?.comment ?? str(ev.key_comment);
  if (comment) login.push({ label: 'Key comment', value: comment, mono: true, tone: k?.suspicious_comment ? 'bad' : undefined });
  if (k) {
    if (!k.found) login.push({ label: 'authorized_keys', value: 'not found in any readable file (another account, or AuthorizedKeysCommand)', tone: 'warn' });
    if (k.command) login.push({ label: 'Forced command', value: k.command, mono: true, tone: 'good' });
    if (k.from) login.push({ label: 'from= restriction', value: k.from, mono: true, tone: 'good' });
    if (k.found) {
      login.push({
        label: 'Options',
        value: k.options?.length ? k.options.join(', ') : 'none (unrestricted: full shell, forwarding)',
        mono: !!k.options?.length,
        tone: k.options?.length ? undefined : 'bad',
      });
    }
    if (k.files?.length) login.push({ label: 'Authorized by', value: k.files.join('\n'), mono: true, tone: k.in_root_and_user ? 'bad' : undefined });
    if (k.in_root_and_user) login.push({ label: 'Placement', value: "same key in root's and another account's authorized_keys", tone: 'bad' });
    if (k.expected) login.push({ label: 'Allowlist', value: 'marked as expected CI', tone: 'good' });
    if (k.line_masked) login.push({ label: 'authorized_keys line', value: k.line_masked, mono: true, tone: 'dim' });
  } else if (str(ev.key_kind)) {
    login.push({ label: 'Key kind', value: String(ev.key_kind) });
  }
  if (ctx?.port) login.push({ label: 'Client port', value: String(ctx.port), mono: true, tone: 'dim' });
  if (login.length) sections.push({ id: 'login', title: 'Login', rows: login });

  const source: DetailRow[] = [];
  if (keys.ip) source.push({ label: 'Address', value: keys.ip, mono: true });
  const s = ctx?.source;
  if (s) {
    source.push({ label: 'Classification', value: sourceLabel(s) ?? s.kind, tone: s.kind === 'public' ? 'warn' : 'good' });
    source.push({ label: 'Reverse DNS', value: s.rdns || 'none', mono: !!s.rdns, tone: s.rdns ? undefined : 'dim' });
    if (s.asn || s.as_org) source.push({ label: 'Network', value: [s.as_org, s.asn ? `AS${s.asn}` : null].filter(Boolean).join(', ') });
    if (s.country) source.push({ label: 'Country', value: s.country });
  }
  if (opts.originLabel) source.push({ label: 'Origin', value: opts.originLabel });
  if (source.length) sections.push({ id: 'source', title: 'Source address', rows: source });

  if (ctx?.failures) {
    const f = ctx.failures;
    const rows: DetailRow[] = [
      { label: 'Window', value: `${Math.round(f.window_s / 60)} min before the login` },
      { label: 'Failures', value: String(f.total), tone: f.same_ip ? 'bad' : f.total ? 'warn' : 'good' },
      { label: 'From this address', value: String(f.same_ip), tone: f.same_ip ? 'bad' : undefined },
      { label: 'From other addresses', value: String(f.other_ips) },
    ];
    if (f.ips?.length) rows.push({ label: 'Addresses', value: f.ips.map((x) => `${x.ip} x${x.count}`).join('\n'), mono: true });
    if (f.users?.length) rows.push({ label: 'Users tried', value: f.users.map((x) => `${x.user} x${x.count}`).join(', '), mono: true });
    if (f.first && f.last) rows.push({ label: 'Span', value: `${utcString(toMs(f.first))} to ${utcString(toMs(f.last))}`, mono: true, tone: 'dim' });
    sections.push({ id: 'failures', title: 'Before this login', rows, note: describeFailures(f, keys.ip ?? undefined) ?? undefined });
  }

  const sess = ctx?.session;
  if (sess && (sess.ci_deploy || sess.duration_s !== undefined || sess.open)) {
    const rows: DetailRow[] = [];
    const ci = sess.ci_deploy;
    if (ci) {
      rows.push({ label: 'ci-deploy', value: ci.decision, tone: /^allow/i.test(ci.decision) ? 'good' : 'bad' });
      if (ci.repo) rows.push({ label: 'Repository', value: ci.repo, mono: true });
      if (ci.action) rows.push({ label: 'Action', value: ci.action, mono: true });
      if (ci.command) rows.push({ label: 'Command', value: shortCommand(ci.command), mono: true });
      if (ci.at) rows.push({ label: 'Logged', value: utcString(toMs(ci.at)), mono: true, tone: 'dim' });
    }
    if (sess.duration_s !== undefined) rows.push({ label: 'Session length', value: duration(sess.duration_s) });
    else if (sess.open) rows.push({ label: 'Session', value: 'still open when the alert was sent', tone: 'dim' });
    sections.push({ id: 'session', title: 'What the session did', rows });
  }

  const raw: DetailRow[] = [];
  if (keys.rule) raw.push({ label: 'Rule', value: keys.rule, mono: true });
  const mod = str(obj(e.metadata)?.module) ?? str(e.module);
  if (mod && mod !== keys.rule) raw.push({ label: 'Module', value: mod, mono: true });
  if (e.description) raw.push({ label: 'Description', value: e.description });
  const msg = str(ev.message);
  if (msg) raw.push({ label: 'Log line', value: msg, mono: true });
  if (e.status) raw.push({ label: 'Status', value: e.status });
  if (raw.length) sections.push({ id: 'raw', title: 'Record', rows: raw });

  if (!ctx && (keys.fingerprint || /ssh/i.test(keys.rule ?? ''))) {
    sections.push({
      id: 'legacy',
      title: 'Login context',
      rows: [],
      note: 'This agent did not send SSH login context (key options, address enrichment, failure window, ci-deploy). Update threatcrush on that server to see it.',
    });
  }

  return {
    title: str(e.title) ?? str(e.message) ?? keys.rule ?? 'Event',
    severity,
    raisedSeverity: raised && raised !== severity ? raised : null,
    verdict: ctx?.verdict ?? null,
    headline: rowSummary(e).text,
    sections,
    keys,
  };
}

export function verdictTone(level: string | undefined): DetailRow['tone'] {
  return level ? VERDICT_TONE[level] : undefined;
}

export { severityRank };
