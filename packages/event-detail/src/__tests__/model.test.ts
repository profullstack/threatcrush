import { describe, expect, it } from 'vitest';
import { detailModel, rowSummary, sshContextOf, hostLocalString } from '../model';
import { buildTimeline, filterTimeline, relationCounts } from '../timeline';
import { applyExpectedKeys } from '../expected-keys';
import { ctx, detection, FP, OTHER_IP, RUNNER_IP } from './fixtures';

describe('rowSummary', () => {
  it('names user, host, key and source in the row', () => {
    const r = rowSummary(detection(ctx()));
    expect(r.text).toBe(`SSH Login Accepted · deploy@web-1 · publickey ED25519 forced-command key "deploy@example/app-2026-11-20" · from ${RUNNER_IP} (GitHub Actions, MICROSOFT-CORP-MSN-AS-BLOCK AS8075, US)`);
    expect(r.verdict?.level).toBe('likely-ci');
  });

  it('falls back to flat evidence for older agents', () => {
    const r = rowSummary({ id: 'x', at: 0, title: 'SSH Login Accepted', username: 'ops', metadata: { evidence: { auth_method: 'publickey', key_comment: 'ops@box' } } });
    expect(r.text).toBe('SSH Login Accepted · user ops · publickey · key "ops@box"');
    expect(r.verdict).toBeNull();
  });
});

describe('detailModel', () => {
  it('shows host-local and UTC time, key options, failures and session', () => {
    const m = detailModel(detection(ctx()));
    expect(m.severity).toBe('low');
    expect(m.raisedSeverity).toBe('critical');
    const rows = Object.fromEntries(m.sections.flatMap((s) => s.rows.map((r) => [`${s.id}.${r.label}`, r.value])));
    expect(rows['when.UTC']).toBe('2026-11-22 03:58:33 UTC');
    expect(rows['when.Host local time']).toBe('2026-11-21 19:58:33 (UTC-08:00)');
    expect(rows['login.Forced command']).toContain('ci-deploy example/app');
    expect(rows['login.authorized_keys line']).toContain('[masked]');
    expect(rows['source.Classification']).toContain('GitHub Actions');
    expect(rows['session.ci-deploy']).toBe('ALLOW');
    expect(rows['session.Session length']).toBe('41s');
    expect(m.sections.find((s) => s.id === 'failures')?.note).toContain('all from OTHER addresses');
  });

  it('never shows a key blob', () => {
    const json = JSON.stringify(detailModel(detection(ctx())));
    expect(json).not.toMatch(/AAAA[A-Za-z0-9+/]{20,}/);
  });

  it('asks for an agent update when an SSH detection has no context', () => {
    const m = detailModel({ id: 'x', at: 0, rule_id: 'ssh-success-after-failures', metadata: { evidence: { fingerprint: FP } } });
    expect(m.sections.find((s) => s.id === 'legacy')).toBeTruthy();
  });

  it('formats negative and positive offsets', () => {
    expect(hostLocalString(Date.UTC(2026, 0, 1, 0, 0, 0), 330)).toBe('2026-01-01 05:30:00 (UTC+05:30)');
  });
});

describe('buildTimeline', () => {
  const primary = detection(ctx());
  const sameIp = { id: 'a', at: '2026-11-22T03:00:00Z', title: 'Port scan', rule_id: 'port-scan', source_ip: RUNNER_IP, server_id: 'srv-2' };
  const sameKey = detection(ctx({ source: { ip: OTHER_IP, kind: 'public' } }), { id: 'b', at: '2026-11-21T10:00:00Z', server_id: 'srv-3', rule_id: 'ssh-login-sensitive' });
  const sameHost = { id: 'c', at: '2026-11-22T04:00:00Z', title: 'Disk', rule_id: 'disk', server_id: 'srv-1' };
  const unrelated = { id: 'd', at: '2026-11-22T04:00:00Z', title: 'x', rule_id: 'x', server_id: 'srv-9', source_ip: '203.0.113.200' };

  it('keeps related events with their relations, newest first, current marked', () => {
    const t = buildTimeline(primary, [sameIp, sameKey, sameHost, unrelated, primary]);
    expect(t.map((i) => i.event.id)).toEqual(['c', 'det-1', 'a', 'b']);
    expect(t.find((i) => i.event.id === 'a')!.relations).toEqual(['ip']);
    expect(t.find((i) => i.event.id === 'b')!.relations).toEqual(['key']);
    expect(t.find((i) => i.event.id === 'c')!.relations).toEqual(['host']);
    expect(t.find((i) => i.current)!.event.id).toBe('det-1');
    expect(relationCounts(t)).toEqual({ all: 3, ip: 1, key: 1, host: 1, rule: 0 });
    expect(filterTimeline(t, 'key').map((i) => i.event.id)).toEqual(['det-1', 'b']);
  });
});

describe('applyExpectedKeys', () => {
  it('turns a listed key into an info row', () => {
    const e = applyExpectedKeys(detection(ctx({ source: { ip: OTHER_IP, kind: 'public' }, session: undefined })), new Set([FP]));
    expect(sshContextOf(e)!.verdict.level).toBe('expected');
    expect(sshContextOf(e)!.verdict.severity).toBe('info');
  });

  it('does not hide a red flag', () => {
    const base = ctx();
    const e = applyExpectedKeys(detection(ctx({ key: { ...base.key!, in_root_and_user: true } })), new Set([FP]));
    expect(sshContextOf(e)!.verdict.level).toBe('suspicious');
  });
});
