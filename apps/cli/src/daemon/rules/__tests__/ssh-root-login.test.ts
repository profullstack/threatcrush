import { describe, expect, it } from 'vitest';
import { DEFAULT_RULES } from '../default-rules.js';

const rule = DEFAULT_RULES.find((r) => r.id === 'ssh-root-login');
// The engine compiles rule regexes case-insensitively.
const re = new RegExp(rule!.match.value as string, 'i');

describe('ssh-root-login rule', () => {
  it('fires for failed SSH logins as root', () => {
    for (const m of [
      'Failed SSH login for root from 45.33.22.11',
      'Failed password for root from 198.51.100.23 port 40001 ssh2',
      'Failed publickey for root from 198.51.100.23 port 22 ssh2',
      'Failed password for invalid user root from 198.51.100.23 port 22 ssh2',
      '[sshd-session] Failed password for root from 198.51.100.23 port 22 ssh2',
    ]) {
      expect(re.test(m), m).toBe(true);
    }
  });

  it('ignores a sudo command that merely says "failed" before "as root"', () => {
    // The exact privilege-watch event that paged a false "Root SSH Login
    // Attempt": a nightly DB backup run through sudo.
    const sudo =
      'sudo: anthony ran /usr/bin/sh -c t=$(mktemp /var/tmp/diskpush-dbbackup.XXXXXX) || exit 1\\n' +
      'sqlite3 /home/customer/apps/app/app.db ".backup $t" || exit 1\\n' +
      'v=$(sqlite3 -readonly "$t" \'PRAGMA quick_check;\')\\n' +
      '[ "$v" = ok ] || { echo "the copy failed its integrity check: $v" >&2; exit 1; }\\n' +
      'cat "$t" as root';
    expect(re.test(sudo)).toBe(false);
  });

  it('ignores other non-attempts', () => {
    for (const m of [
      'sudo denied: bob tried /usr/bin/false as root',
      'SSH login accepted for root',
      'Failed SSH login for anthony from 45.33.22.11',
      'Failed SSH login for rootless from 45.33.22.11',
      '[systemd] backup.service failed; restarting as root',
    ]) {
      expect(re.test(m), m).toBe(false);
    }
  });
});
