import { describe, it, expect } from 'vitest';
import { JournalProvenance } from '../watchers/journal-provenance.js';
const record = (message: string, overrides: Record<string, unknown> = {}) => ({ _UID: '0', _COMM: 'sshd-session', _PID: '321', _BOOT_ID: 'boot-a', __CURSOR: 'cursor-a', __REALTIME_TIMESTAMP: '1800000000000000', MESSAGE: message, ...overrides });
describe('journal connection provenance', () => {
  it('correlates a missing peer only within the same boot and process, and retains locator fields', () => {
    const p = new JournalProvenance();
    p.fields(record('Connection from 192.0.2.5 port 1234'));
    expect(p.fields(record('fatal: incomplete message [preauth]'))).toMatchObject({ source_ip: '192.0.2.5', details: { pid: '321', boot_id: 'boot-a', journal_cursor: 'cursor-a', source_ip_basis: 'same boot and sshd PID within 120 seconds' } });
    expect(p.fields(record('fatal', { _PID: '322' })).source_ip).toBeUndefined();
    expect(p.fields(record('fatal', { _BOOT_ID: 'boot-b' })).source_ip).toBeUndefined();
  });
  it('rejects spoofed tags and expired context', () => {
    const p = new JournalProvenance();
    p.fields(record('Connection from 192.0.2.6', { _UID: '1000', SYSLOG_IDENTIFIER: 'sshd' }));
    expect(p.fields(record('fatal')).source_ip).toBeUndefined();
    p.fields(record('Connection from 192.0.2.5'));
    expect(p.fields(record('fatal', { __REALTIME_TIMESTAMP: '1800000121000000' })).source_ip).toBeUndefined();
  });
  it('does not correlate when the boot or timestamp is unavailable', () => {
    const p = new JournalProvenance();
    p.fields(record('Connection from 192.0.2.5', { _BOOT_ID: undefined }));
    expect(p.fields(record('fatal')).source_ip).toBeUndefined();
    p.fields(record('Connection from 192.0.2.5'));
    expect(p.fields(record('fatal', { __REALTIME_TIMESTAMP: undefined })).source_ip).toBeUndefined();
  });
});
