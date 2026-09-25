import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { FirewallAdapter } from '../firewall/adapters.js';
import type { ThreatEvent } from '../../types/events.js';
import { DEFAULT_RULES } from '../rules/default-rules.js';

vi.mock('../../core/state.js', () => ({
  getModuleState: () => undefined,
  setModuleState: () => {},
}));

const { RemediationManager, isSuccessfulAuth } = await import('../firewall/remediation.js');

class FakeAdapter implements FirewallAdapter {
  name = 'fake';
  enforces = true;
  blocked = new Set<string>();
  isAvailable(): boolean { return true; }
  async block(ip: string): Promise<void> { this.blocked.add(ip); }
  async unblock(ip: string): Promise<void> { this.blocked.delete(ip); }
  async isBlocked(ip: string): Promise<boolean> { return this.blocked.has(ip); }
  async listBlocked(): Promise<string[]> { return [...this.blocked]; }
}

const bus = { publish: () => {}, on: () => {}, announceModule: () => {} } as never;

function event(partial: Partial<ThreatEvent>): ThreatEvent {
  return {
    timestamp: new Date(),
    module: 'rule-engine',
    category: 'auth',
    severity: 'critical',
    message: 'test',
    source_ip: '45.33.22.11',
    ...partial,
  };
}

describe('a successful login is never a ban', () => {
  let adapter: FakeAdapter;
  const make = () => new RemediationManager(adapter, bus, { protect_current_ssh_client: false });

  beforeEach(() => { adapter = new FakeAdapter(); });

  it('does not ban on "SSH login accepted", even at critical', async () => {
    // The lockout: `ssh-success-after-failures` is critical with threshold 1
    // and matches this message, so every successful ssh login banned the
    // person who had just logged in.
    const manager = make();
    await manager.handleDetection(event({
      message: '[DETECTION] SSH login accepted for anthony',
      details: { rule_id: 'ssh-success-after-failures' },
    }));
    expect(manager.getBlocklist()).toHaveLength(0);
    expect(adapter.blocked.size).toBe(0);
  });

  it('does not ban on an accepted publickey line from ssh-guard', async () => {
    const manager = make();
    await manager.handleDetection(event({
      module: 'ssh-guard',
      message: 'Accepted publickey for anthony from 45.33.22.11',
    }));
    expect(manager.getBlocklist()).toHaveLength(0);
  });

  it('still bans a failed login', async () => {
    const manager = make();
    await manager.handleDetection(event({
      module: 'ssh-guard',
      severity: 'high',
      message: 'Failed SSH login for root from 45.33.22.11',
    }));
    expect(manager.getBlocklist()).toHaveLength(1);
  });

  it('recognises the spellings that matter', () => {
    for (const line of [
      'SSH login accepted for anthony',
      'Accepted publickey for anthony from 1.2.3.4',
      'Accepted password for root from 1.2.3.4',
      'pam_unix(sshd:session): session opened for user anthony',
    ]) {
      expect(isSuccessfulAuth(line), line).toBe(true);
    }
    expect(isSuccessfulAuth('Failed password for root from 1.2.3.4')).toBe(false);
    expect(isSuccessfulAuth('Invalid user admin from 1.2.3.4')).toBe(false);
  });
});

describe('a rule bans only when it asks to', () => {
  let adapter: FakeAdapter;
  const make = () => new RemediationManager(adapter, bus, { protect_current_ssh_client: false });

  beforeEach(() => { adapter = new FakeAdapter(); });

  it('ignores a critical rule that declares no remediation', async () => {
    // Banning on severity alone means any rule author who writes `critical`
    // writes a firewall rule by accident.
    const manager = make();
    await manager.handleDetection(event({
      message: '[DETECTION] Critical system error',
      details: { rule_id: 'system-critical-error' },
    }));
    expect(manager.getBlocklist()).toHaveLength(0);
  });

  it('bans when the rule declares action: block', async () => {
    const manager = make();
    await manager.handleDetection(event({
      message: '[DETECTION] SQL injection attempt',
      details: { rule_id: 'web-sqli-attack', remediation: { action: 'block', ttl_seconds: 3600 } },
    }));
    expect(manager.getBlocklist()).toHaveLength(1);
  });

  it('leaves module events judged on severity alone', async () => {
    // Only rule-engine detections carry a rule_id; a module's own event is
    // still governed by min_severity.
    const manager = make();
    await manager.handleDetection(event({
      module: 'log-watcher',
      message: 'Attack [SQLI]: GET /search',
      details: undefined,
    }));
    expect(manager.getBlocklist()).toHaveLength(1);
  });
});

describe('the shipped rules', () => {
  it('never ban on an accepted login', () => {
    for (const rule of DEFAULT_RULES) {
      if (rule.remediation?.action !== 'block') continue;
      const pattern = String(rule.match?.value ?? '');
      expect(pattern, `${rule.id} must not match an accepted auth`).not.toMatch(/accepted/i);
    }
  });
});
