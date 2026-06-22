import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { parseAuthLog } from './log-parser.ts';

describe('parseAuthLog', () => {
  it('extracts IPv4 addresses from SSH failures', () => {
    const entry = parseAuthLog(
      'Apr  4 12:00:00 server sshd[1234]: Failed password for root from 203.0.113.10 port 54321 ssh2',
    );

    assert.equal(entry?.fields.ip, '203.0.113.10');
    assert.equal(entry?.fields.user, 'root');
  });

  it('extracts IPv6 addresses from SSH failures', () => {
    const entry = parseAuthLog(
      'Apr  4 12:00:00 server sshd[1234]: Failed password for root from 2001:db8::42 port 54321 ssh2',
    );

    assert.equal(entry?.fields.ip, '2001:db8::42');
    assert.equal(entry?.fields.user, 'root');
  });
});
