import { describe, expect, it } from 'vitest';
import { computeVerdict, describeFailures } from '../verdict';
import { ctx, OTHER_IP, RUNNER_IP } from './fixtures';

describe('computeVerdict', () => {
  it('calls a GitHub Actions login with a forced-command key and ci-deploy ALLOW a likely CI deploy', () => {
    const v = ctx().verdict;
    expect(v.level).toBe('likely-ci');
    expect(v.severity).toBe('low');
    expect(v.summary).toBe('Likely CI deploy: GitHub Actions IP, forced-command deploy key, ci-deploy ALLOW deploy app 5addb4f2');
  });

  it('flags an unrestricted key from a non-CI address as suspicious', () => {
    const v = ctx({
      source: { ip: OTHER_IP, kind: 'public', asn: 64500, as_org: 'EXAMPLE-NET', country: 'NL' },
      key: { found: true, type: 'ssh-ed25519', fingerprint: 'SHA256:x', comment: 'me@laptop', options: [], command: null, from: null, restrict: false },
      session: undefined,
    }).verdict;
    expect(v.level).toBe('suspicious');
    expect(v.severity).toBe('critical');
    expect(v.summary).toContain('unrestricted key (no command=, from= or restrict) from a non-CI address');
  });

  it('keeps critical when the key is in root and a user file even from GitHub Actions', () => {
    const base = ctx();
    const v = ctx({ key: { ...base.key!, in_root_and_user: true } }).verdict;
    expect(v.level).toBe('suspicious');
    expect(v.severity).toBe('critical');
    expect(v.reasons).toContain('the same key authorizes root and another account');
  });

  it('treats a dated diag comment on an unrestricted key as critical', () => {
    const v = ctx({
      source: { ip: OTHER_IP, kind: 'public' },
      key: { found: true, type: 'ssh-ed25519', fingerprint: 'SHA256:y', comment: 'ci-diag-20261120', options: [], command: null, from: null, restrict: false, suspicious_comment: true },
      session: undefined,
    }).verdict;
    expect(v.severity).toBe('critical');
    expect(v.reasons.join(' ')).toContain('ci-diag-20261120');
  });

  it('calls failures from the same address before success a possible brute force', () => {
    const v = ctx({ failures: { window_s: 600, total: 4, same_ip: 4, other_ips: 0 } }).verdict;
    expect(v.level).toBe('suspicious');
    expect(v.reasons[0]).toMatch(/4 failed attempt\(s\) from this same address/);
  });

  it('collapses an expected CI key to info', () => {
    const base = ctx();
    const v = ctx({ key: { ...base.key!, expected: true } }).verdict;
    expect(v.level).toBe('expected');
    expect(v.severity).toBe('info');
  });

  it('marks a ci-deploy DENY for review', () => {
    const v = ctx({ session: { ci_deploy: { decision: 'DENY', repo: 'example/app' } } }).verdict;
    expect(v.severity).toBe('high');
    expect(v.reasons).toContain('ci-deploy DENIED example/app');
  });

  it('treats Tailscale and loopback logins as internal', () => {
    expect(ctx({ source: { ip: '100.64.1.2', kind: 'tailscale' }, session: undefined }).verdict.level).toBe('internal');
    expect(ctx({ source: { ip: '127.0.0.1', kind: 'loopback' }, session: undefined }).verdict.severity).toBe('low');
  });

  it('flags a password login from the internet', () => {
    const v = ctx({ auth_method: 'password', key: undefined, source: { ip: OTHER_IP, kind: 'public' }, session: undefined }).verdict;
    expect(v.severity).toBe('critical');
  });
});

describe('describeFailures', () => {
  it('says plainly when the failures came from other addresses', () => {
    const t = describeFailures(ctx().failures, RUNNER_IP)!;
    expect(t).toContain('all from OTHER addresses');
    expect(t).toContain(`${OTHER_IP} x2`);
    expect(t).toContain('not a brute force that succeeded');
  });

  it('says when there were none', () => {
    expect(describeFailures({ window_s: 600, total: 0, same_ip: 0, other_ips: 0 })).toMatch(/^No failed SSH attempts in the 10 min/);
  });
});
