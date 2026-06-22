import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { parseAuthLog } from './log-parser.ts';

describe('parseAuthLog', () => {
  it('extracts the attempted username from invalid user SSH failures', () => {
    const entry = parseAuthLog(
      'Apr  4 12:00:00 server sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 54321 ssh2',
    );

    assert.equal(entry?.fields.user, 'admin');
    assert.equal(entry?.fields.ip, '203.0.113.10');
  });

  it('keeps extracting usernames from normal SSH failures', () => {
    const entry = parseAuthLog(
      'Apr  4 12:00:00 server sshd[1234]: Failed password for root from 203.0.113.10 port 54321 ssh2',
    );

    assert.equal(entry?.fields.user, 'root');
    assert.equal(entry?.fields.ip, '203.0.113.10');
  });
});
