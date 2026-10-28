import { describe, expect, it } from 'vitest';
import { sshArgv, sshTargetError } from '../connect.js';

describe('threatcrush connect: values from the API never become ssh options', () => {
  it('refuses an option-looking user or host', () => {
    expect(sshTargetError({ hostname: 'box.example.com', username: '-oProxyCommand=sh -c id', port: 22 })).toMatch(/ssh user/);
    expect(sshTargetError({ hostname: '-oProxyCommand=id', username: 'root', port: 22 })).toMatch(/hostname/);
    expect(sshTargetError({ hostname: 'box.example.com', username: 'root', port: Number.NaN })).toMatch(/port/);
  });

  it('accepts normal targets and ends options before the destination', () => {
    expect(sshTargetError({ hostname: 'dev2.profullstack.com', username: 'deploy', port: 2222 })).toBeNull();
    expect(sshTargetError({ hostname: '2001:db8::1', username: 'root', port: 22 })).toBeNull();
    expect(sshArgv({ hostname: 'h.example', username: 'root', port: 22, identity: '/k' }))
      .toEqual(['-p', '22', '-i', '/k', '--', 'root@h.example']);
  });
});
