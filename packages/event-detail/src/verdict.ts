import type { FailureContext, Severity, SshLoginContext, Verdict, VerdictLevel } from './types';

const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function maxSeverity(a: Severity, b: Severity): Severity {
  return RANK[a] >= RANK[b] ? a : b;
}

export function severityRank(s: string | null | undefined): number {
  return RANK[(s ?? 'info') as Severity] ?? 0;
}

/** A short name for a forced command: `ci-deploy owner/repo` rather than a full path. */
export function shortCommand(command: string): string {
  const parts = command.trim().split(/\s+/);
  const bin = (parts[0] ?? '').split('/').pop() ?? '';
  return [bin, ...parts.slice(1)].join(' ').slice(0, 160);
}

/** Plain words for what happened before the login, or null when nothing is known. */
export function describeFailures(f: FailureContext | undefined, ip?: string): string | null {
  if (!f) return null;
  const mins = Math.max(1, Math.round(f.window_s / 60));
  if (f.total === 0) {
    return `No failed SSH attempts in the ${mins} min before this login (the rule fires on every accepted login).`;
  }
  const top = (f.ips ?? []).filter((x) => x.ip !== ip).slice(0, 3).map((x) => `${x.ip} x${x.count}`).join(', ');
  const users = (f.users ?? []).slice(0, 4).map((u) => u.user).join(', ');
  const span = f.first && f.last ? ` between ${hhmmss(f.first)} and ${hhmmss(f.last)} UTC` : '';
  if (f.same_ip > 0 && f.other_ips === 0) {
    return `${f.same_ip} failed attempt${f.same_ip === 1 ? '' : 's'} from this same address${span}${users ? ` (users: ${users})` : ''}, then this login succeeded: a guessed or brute-forced credential is possible.`;
  }
  if (f.same_ip === 0) {
    return `${f.total} failed attempt${f.total === 1 ? '' : 's'} in the ${mins} min before, all from OTHER addresses${top ? ` (${top})` : ''}${users ? `, users: ${users}` : ''}. None came from this address, so this is not a brute force that succeeded.`;
  }
  return `${f.total} failed attempt${f.total === 1 ? '' : 's'} in the ${mins} min before: ${f.same_ip} from this address and ${f.other_ips} from others${top ? ` (${top})` : ''}${users ? `, users: ${users}` : ''}.`;
}

function hhmmss(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(11, 19);
}

/**
 * Why this accepted login is or is not worth a look, from the context the
 * agent collected. Pure: the agent computes it before upload and the web and
 * desktop recompute nothing, so all three say the same thing.
 *
 *   expected    an operator marked the key as expected CI          -> info
 *   likely-ci   GitHub Actions address + forced-command key, and
 *               ci-deploy did not deny it                          -> low
 *   internal    loopback, this host, Tailscale or a private range  -> low
 *   review      anything not clearly fine or clearly bad           -> high
 *   suspicious  unrestricted key from a non-CI public address,
 *               password login from the internet, a key in both
 *               root's and a user's file, a dated ci/diag comment,
 *               failures from the same address first               -> critical
 */
export function computeVerdict(ctx: Omit<SshLoginContext, 'verdict'>): Verdict {
  const reasons: string[] = [];
  const key = ctx.key;
  const src = ctx.source;
  const ci = ctx.session?.ci_deploy;
  const forced = !!key?.command;
  const restricted = forced || !!key?.from;
  const publicSrc = !src || src.kind === 'public' || src.kind === 'github-actions';
  const ghActions = src?.kind === 'github-actions';
  let severity: Severity = 'info';
  let level: VerdictLevel = 'review';
  const raise = (s: Severity, why: string) => { severity = maxSeverity(severity, s); reasons.push(why); };

  // Red flags first: they hold whatever else is true.
  if (key?.in_root_and_user) raise('critical', 'the same key authorizes root and another account');
  if (key?.suspicious_comment) raise(restricted ? 'high' : 'critical', `key comment "${key.comment}" looks like a dated temporary CI/diagnostic key`);
  if (ctx.failures && ctx.failures.same_ip > 0) raise('critical', `${ctx.failures.same_ip} failed attempt(s) from this same address before it succeeded`);
  if (ci && /^deny/i.test(ci.decision)) raise('high', `ci-deploy DENIED${ci.repo ? ` ${ci.repo}` : ''}`);
  if (publicSrc && ctx.auth_method === 'password') raise('critical', 'password login from a public address');
  if (publicSrc && !ghActions && key?.found && !restricted && !key.restrict) raise('critical', 'unrestricted key (no command=, from= or restrict) from a non-CI address');
  if (publicSrc && key && !key.found && ctx.auth_method === 'publickey') raise('high', 'key not found in any readable authorized_keys (another account, or AuthorizedKeysCommand)');
  if (forced && publicSrc && !ghActions) raise('medium', 'forced-command key used from an address outside GitHub Actions');

  const red = severityRank(severity) >= RANK.high;
  if (key?.expected && !red) {
    level = 'expected';
    severity = 'info';
    reasons.unshift(`key marked as expected CI${key.comment ? ` (${key.comment})` : ''}`);
  } else if (ghActions && forced && !red) {
    level = 'likely-ci';
    severity = 'low';
    reasons.unshift('GitHub Actions IP', 'forced-command deploy key');
    if (ci && /^allow/i.test(ci.decision)) reasons.push(`ci-deploy ALLOW ${ci.action || ci.repo || ''}`.trim());
  } else if (src && ['loopback', 'self', 'tailscale', 'private'].includes(src.kind) && !red) {
    level = 'internal';
    severity = maxSeverity('low', severity);
    reasons.unshift(src.kind === 'tailscale' ? 'Tailscale address' : src.kind === 'self' ? "one of this host's own addresses" : src.kind === 'loopback' ? 'loopback' : 'private address');
  } else if (red) {
    level = 'suspicious';
  } else {
    severity = maxSeverity('high', severity);
    if (!reasons.length) reasons.push(ghActions ? 'GitHub Actions address but not a forced-command key' : 'login from a public address');
  }

  return { level, severity, summary: verdictSummary(level, reasons, ctx), reasons };
}

function verdictSummary(level: VerdictLevel, reasons: string[], ctx: Omit<SshLoginContext, 'verdict'>): string {
  const head: Record<VerdictLevel, string> = {
    expected: 'Expected CI key',
    'likely-ci': 'Likely CI deploy',
    internal: 'Internal login',
    review: 'Review',
    suspicious: 'Suspicious login',
  };
  if (level === 'review' && reasons.length === 1 && /public address$/.test(reasons[0])) {
    const restricted = ctx.key?.command || ctx.key?.from;
    return `${head.review}: ${restricted ? 'restricted' : 'unrestricted'} ${ctx.auth_method ?? 'login'} from ${ctx.source?.ip ?? 'a public address'}`;
  }
  return `${head[level]}: ${reasons.join(', ')}`;
}
