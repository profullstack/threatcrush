import type { EventLike, SshLoginContext } from '../types';
import { computeVerdict } from '../verdict';

/** Documentation addresses only (RFC 5737 / 3849). */
export const RUNNER_IP = '192.0.2.10';
export const OTHER_IP = '198.51.100.7';
export const THIRD_IP = '203.0.113.9';
export const FP = 'SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg';

export function ctx(over: Partial<Omit<SshLoginContext, 'verdict'>> = {}): SshLoginContext {
  const base: Omit<SshLoginContext, 'verdict'> = {
    v: 1,
    at: '2026-11-22T03:58:33.000Z',
    host: 'web-1',
    tz_offset_min: -480,
    user: 'deploy',
    auth_method: 'publickey',
    port: 33792,
    key: {
      found: true,
      type: 'ssh-ed25519',
      fingerprint: FP,
      comment: 'deploy@example/app-2026-11-20',
      options: ['restrict', 'command="/home/deploy/.local/bin/ci-deploy example/app"'],
      command: '/home/deploy/.local/bin/ci-deploy example/app',
      from: null,
      restrict: true,
      files: ['/home/deploy/.ssh/authorized_keys:3'],
      accounts: ['deploy'],
      line_masked: 'restrict,command="/home/deploy/.local/bin/ci-deploy example/app" ssh-ed25519 AAAAC3Nz…[masked] deploy@example/app-2026-11-20',
    },
    source: { ip: RUNNER_IP, kind: 'github-actions', rdns: null, asn: 8075, as_org: 'MICROSOFT-CORP-MSN-AS-BLOCK', country: 'US' },
    failures: { window_s: 600, total: 3, same_ip: 0, other_ips: 3, ips: [{ ip: OTHER_IP, count: 2 }, { ip: THIRD_IP, count: 1 }], users: [{ user: 'root', count: 2 }, { user: 'admin', count: 1 }], first: '2026-11-22T03:50:01.000Z', last: '2026-11-22T03:57:40.000Z' },
    session: { ci_deploy: { decision: 'ALLOW', repo: 'example/app', action: 'deploy app 5addb4f2', command: '/srv/deploy-app.sh 5addb4f2', at: '2026-11-22T03:58:34.000Z' }, duration_s: 41 },
    ...over,
  };
  return { ...base, verdict: computeVerdict(base) };
}

export function detection(c: SshLoginContext, over: Partial<EventLike> = {}): EventLike {
  return {
    id: 'det-1',
    at: c.at,
    severity: 'critical',
    title: 'SSH Login Accepted',
    rule_id: 'ssh-success-after-failures',
    source_ip: c.source?.ip ?? null,
    server_id: 'srv-1',
    host: 'web-1',
    metadata: { module: 'rule-engine', evidence: { module: 'ssh-guard', message: `SSH login accepted for ${c.user}`, fingerprint: c.key?.fingerprint, ssh_context: c } },
    ...over,
  };
}
