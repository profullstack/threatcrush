import { describe, expect, it } from 'vitest';
import { DEFAULT_RULES } from '../default-rules.js';
import { RuleEngine } from '../engine.js';
import type { ThreatEvent } from '../../../types/events.js';

/**
 * The incident this came from: b85be4b9 on dev3, "Critical System Error",
 * critical, 8 raises since 2026-10-28 — SSH bots from China and Singapore that
 * never authenticated, sharing one incident with local `sudo` password typos,
 * because every one of those lines is syslog priority 2 and so matched
 * `system-critical-error`. The page named none of it.
 */
function fire(event: Partial<ThreatEvent> & { message: string }): string[] {
  const fired: string[] = [];
  const engine = new RuleEngine((d) => fired.push(d.rule_id));
  engine.loadRules(DEFAULT_RULES);
  engine.evaluate({
    timestamp: new Date(),
    module: 'user-journal',
    category: 'system',
    severity: 'critical',
    ...event,
  } as ThreatEvent);
  return fired;
}

// journal-watcher's real wording: `[${SYSLOG_IDENTIFIER}] ${MESSAGE}`.
const PREAUTH = '[sshd-session] fatal: userauth_pubkey: parse publickey packet: incomplete message [preauth]';
const BANNER = '[sshd-session] banner exchange: Connection from 117.132.151.234 port 49175: invalid format';
const SUDO = '[sudo] pam_unix(sudo:auth): auth could not identify password for [anthony]';

describe('ssh-preauth-rejected', () => {
  it('claims a rejected sshd handshake, and system-critical-error does not', () => {
    for (const message of [PREAUTH, BANNER, '[sshd] fatal: userauth_pubkey: parse publickey packet: incomplete message [preauth]']) {
      const fired = fire({ message, source_ip: '117.132.151.234' });
      expect(fired, message).toContain('ssh-preauth-rejected');
      expect(fired, message).not.toContain('system-critical-error');
    }
  });

  it('leaves every other critical line to system-critical-error', () => {
    // Including one with no `process`/identifier at all: the exclusion matches
    // on `message` precisely so these keep firing. An `and` on an undefined
    // field would have silenced the generic rule for all of them.
    for (const message of [SUDO, '[kernel] EXT4-fs error (device sda1): ext4_journal_check_start', 'something with no identifier prefix at all']) {
      const fired = fire({ message });
      expect(fired, message).toContain('system-critical-error');
      expect(fired, message).not.toContain('ssh-preauth-rejected');
    }
  });

  it('separates the two into their own incidents', () => {
    // store.ts keys an incident by `detection:<server>:<rule_id>`, so the split
    // is what stops an SSH bot and a sudo typo sharing one page.
    expect(fire({ message: PREAUTH })).not.toEqual(fire({ message: SUDO }));
  });

  it('still pages: critical is what store.ts pages on', () => {
    const rule = DEFAULT_RULES.find((r) => r.id === 'ssh-preauth-rejected');
    expect(rule?.severity).toBe('critical');
    // Reporting only. The ban comes from the ssh-* rules that match the
    // "Invalid user" line, which carries an address to ban.
    expect(rule?.remediation).toBeUndefined();
  });

  it('ignores a non-critical sshd line', () => {
    expect(fire({ message: PREAUTH, severity: 'info' })).toEqual([]);
  });
});
