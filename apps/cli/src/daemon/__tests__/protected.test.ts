import { describe, it, expect } from 'vitest';
import {
  DEFAULT_PROTECTED,
  currentSshClient,
  ipMatches,
  ipToBytes,
  isProtected,
} from '../firewall/protected.js';

describe('ipToBytes', () => {
  it('reads IPv4', () => {
    expect([...(ipToBytes('192.168.1.1') ?? [])]).toEqual([192, 168, 1, 1]);
  });

  it('reads IPv6, compressed and full', () => {
    expect(ipToBytes('::1')?.length).toBe(16);
    expect([...(ipToBytes('::1') ?? [])].slice(-2)).toEqual([0, 1]);
    expect(ipToBytes('2001:0db8:0000:0000:0000:0000:0000:0001')).toEqual(ipToBytes('2001:db8::1'));
  });

  it('ignores a zone id', () => {
    expect(ipToBytes('fe80::1%eth0')).toEqual(ipToBytes('fe80::1'));
  });

  it('rejects what is not an address', () => {
    expect(ipToBytes('not-an-ip')).toBeNull();
    expect(ipToBytes('999.1.1.1')).toBeNull();
  });
});

describe('ipMatches', () => {
  it('matches inside a v4 CIDR and not outside it', () => {
    expect(ipMatches('10.4.5.6', '10.0.0.0/8')).toBe(true);
    expect(ipMatches('11.4.5.6', '10.0.0.0/8')).toBe(false);
  });

  it('handles prefixes that are not whole octets', () => {
    expect(ipMatches('172.16.0.1', '172.16.0.0/12')).toBe(true);
    expect(ipMatches('172.32.0.1', '172.16.0.0/12')).toBe(false);
  });

  it('matches a bare address exactly', () => {
    expect(ipMatches('203.0.113.7', '203.0.113.7')).toBe(true);
    expect(ipMatches('203.0.113.8', '203.0.113.7')).toBe(false);
  });

  it('never matches across address families', () => {
    // A v4 address quietly matching a v6 range is how a "protected" check
    // passes something it meant to stop.
    expect(ipMatches('10.0.0.1', 'fc00::/7')).toBe(false);
    expect(ipMatches('fc00::1', '10.0.0.0/8')).toBe(false);
  });

  it('matches inside a v6 prefix', () => {
    expect(ipMatches('fe80::1', 'fe80::/10')).toBe(true);
    expect(ipMatches('2001:db8::1', 'fe80::/10')).toBe(false);
  });

  it('rejects a malformed prefix rather than matching everything', () => {
    expect(ipMatches('10.0.0.1', '10.0.0.0/99')).toBe(false);
    expect(ipMatches('10.0.0.1', '10.0.0.0/abc')).toBe(false);
  });
});

describe('isProtected with the built-in set', () => {
  it('protects loopback, private ranges and link-local', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.0.5', '172.20.0.1', '169.254.1.1', '::1', 'fe80::1']) {
      expect(isProtected(ip, DEFAULT_PROTECTED), ip).toBe(true);
    }
  });

  it('leaves public addresses bannable', () => {
    for (const ip of ['45.33.22.11', '185.220.101.44', '2001:db8::1']) {
      expect(isProtected(ip, DEFAULT_PROTECTED), ip).toBe(false);
    }
  });
});

describe('currentSshClient', () => {
  it('takes the client address out of SSH_CLIENT', () => {
    expect(currentSshClient({ SSH_CLIENT: '203.0.113.7 51234 22' } as NodeJS.ProcessEnv)).toBe('203.0.113.7');
  });

  it('falls back to SSH_CONNECTION', () => {
    expect(
      currentSshClient({ SSH_CONNECTION: '203.0.113.7 51234 10.0.0.1 22' } as NodeJS.ProcessEnv),
    ).toBe('203.0.113.7');
  });

  it('is null off an SSH session, and on junk', () => {
    expect(currentSshClient({} as NodeJS.ProcessEnv)).toBeNull();
    expect(currentSshClient({ SSH_CLIENT: 'nonsense here' } as NodeJS.ProcessEnv)).toBeNull();
  });
});
