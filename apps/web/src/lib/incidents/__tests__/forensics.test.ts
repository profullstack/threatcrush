import { describe, expect, it } from 'vitest';
import { forensicEvidence } from '../forensics';
describe('forensic evidence presentation', () => {
  it('does not identify the root logging process as an authenticated remote actor', () => {
    const e = forensicEvidence({ id: 'd', server_id: 's', rule_id: 'r', detected_at: '2026-10-30T17:29:41Z', username: null, source_ip: null, raw_metadata: { evidence: { message: 'fatal: incomplete message [preauth]', system_account: 'root', system_uid: '0', pid: '123' }, authorization: 'never return arbitrary metadata' } });
    expect(e.logging_account).toBe('root');
    expect(e.target_account).toBeNull();
    expect(e.source_ip).toBeNull();
    expect(e.command).toBeNull();
    expect(e.attribution).toContain('before authentication');
    expect(e).not.toHaveProperty('authorization');
    expect(e.next_steps.join(' ')).toContain('does not prove compromise');
  });

  it('recovers an SSH target account from preserved evidence when the database field is empty', () => {
    const e = forensicEvidence({ id: 'd', server_id: 's', rule_id: 'ssh-success-after-failures', detected_at: '2026-10-31T08:07:07Z', username: null, source_ip: '20.169.68.241', raw_metadata: { evidence: { module: 'ssh-guard', message: 'SSH login accepted for anthony' } } });
    expect(e.target_account).toBe('anthony');
    expect(e.next_steps.join(' ')).toContain('not proof of compromise');
    expect(e.next_steps.join(' ')).toContain('does not execute these server changes');
  });
});
