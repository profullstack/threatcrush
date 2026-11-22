import type { EventLike, SshLoginContext } from './types';
import { fingerprintOf, sshContextOf } from './model';

/**
 * Applies an operator's "expected CI key" allowlist on the viewer's side: a
 * login with a listed fingerprint is shown as the quiet info row the agent
 * would have sent had it known. The agent applies the same list itself when
 * it has it (`[ssh_context] expected_keys`, or the desktop app's push to the
 * local daemon); this covers servers whose agent does not.
 *
 * Red flags still win: a key in root's file too, a dated diag comment or
 * failures from the same address keep the agent's verdict.
 */
export function applyExpectedKeys<T extends EventLike>(e: T, expected: ReadonlySet<string>): T {
  const fp = fingerprintOf(e);
  const ctx = sshContextOf(e);
  if (!fp || !expected.has(fp) || !ctx || ctx.verdict.level === 'expected') return e;
  const red = ctx.key?.in_root_and_user || ctx.key?.suspicious_comment || (ctx.failures?.same_ip ?? 0) > 0;
  if (red) return e;
  const next: SshLoginContext = {
    ...ctx,
    key: { ...(ctx.key ?? { found: false }), expected: true },
    verdict: {
      level: 'expected',
      severity: 'info',
      summary: `Expected CI key${ctx.key?.comment ? `: ${ctx.key.comment}` : ''} (allowlisted in this app)`,
      reasons: ['key marked as expected CI', ...ctx.verdict.reasons],
    },
  };
  const m = (e.metadata ?? {}) as Record<string, unknown>;
  const ev = m.evidence && typeof m.evidence === 'object' ? (m.evidence as Record<string, unknown>) : null;
  const metadata = ev ? { ...m, evidence: { ...ev, ssh_context: next } } : { ...m, ssh_context: next };
  return { ...e, metadata };
}
