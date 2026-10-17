import { describe, expect, it } from 'vitest';
import { admGid } from '../ipc-server.js';

const noAuthLog = () => { throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); };

describe('admGid', () => {
  it('finds adm in /etc/group on a journald-only box with no auth.log (bbs)', () => {
    expect(admGid(() => 'root:x:0:\nsys:x:3:\nadm:x:4:\n', noAuthLog)).toBe(4);
  });

  it('does not confuse a group whose name only starts with adm', () => {
    expect(admGid(() => 'admin:x:1004:\nadm:x:4:syslog\n', noAuthLog)).toBe(4);
  });

  it('falls back to the group of /var/log/auth.log', () => {
    expect(admGid(() => 'root:x:0:\n', () => ({ gid: 4 }))).toBe(4);
  });

  it('is null when neither exists, leaving the socket root:root', () => {
    expect(admGid(() => { throw new Error('EACCES'); }, noAuthLog)).toBeNull();
  });
});
