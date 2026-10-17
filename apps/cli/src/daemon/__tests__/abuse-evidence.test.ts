import { describe, it, expect } from 'vitest';
import {
  NEVER_REPORT_RANGES,
  abuseipdbCategories,
  isReportable,
  summarizeEvidence,
  type ReportabilityConfig,
} from '../workers/abuse-evidence.js';
import { buildComment } from '../workers/abuse-destinations.js';
import { resolveConfig } from '../workers/abuse-config.js';
import type { ThreatEvent, EventCategory } from '../../types/events.js';

const NOW = Date.UTC(2026, 0, 1, 12, 0, 0);

function ev(category: EventCategory, module: string, ageMs: number, ruleId?: string): ThreatEvent {
  return {
    timestamp: new Date(NOW - ageMs),
    module,
    category,
    severity: 'high',
    message: 'attack from host nginx /admin/login.php user=root', // deliberately sensitive
    source_ip: '198.51.100.9',
    details: ruleId ? { rule_id: ruleId } : undefined,
  };
}

const BAR: ReportabilityConfig = {
  minCorroboratingSignals: 2,
  coolingOffSeconds: 3600,
  neverReport: NEVER_REPORT_RANGES,
};

describe('summarizeEvidence', () => {
  it('counts distinct detectors and ignores our own block events', () => {
    const e = summarizeEvidence([
      ev('web', 'rule-engine', 10_000),
      ev('auth', 'ssh-guard', 20_000),
      { ...ev('system', 'firewall-rules', 5_000), message: 'Banned' },
    ]);
    expect(e.signals).toBe(2);
    expect(e.total).toBe(2);
    expect(e.connectionVerified).toBe(true);
  });

  it('marks L3/L4-only evidence as not connection-verified', () => {
    const e = summarizeEvidence([ev('network', 'port-scan', 10_000), ev('scan', 'nmap-watch', 20_000)]);
    expect(e.connectionVerified).toBe(false);
  });

  it('treats a honeypot module as connection-verified regardless of category', () => {
    const e = summarizeEvidence([ev('system', 'ssh-honeypot', 10_000)]);
    expect(e.connectionVerified).toBe(true);
  });
});

describe('isReportable — the third-party-safety bar', () => {
  const good = summarizeEvidence([ev('web', 'rule-engine', 7_200_000), ev('auth', 'ssh-guard', 7_100_000)]);

  it('reports a public, corroborated, handshake-verified, aged source', () => {
    expect(isReportable('198.51.100.9', good, { ...BAR, neverReport: ['10.0.0.0/8'] }, NOW).reportable).toBe(true);
  });

  it('NEVER reports private ranges', () => {
    for (const ip of ['10.1.2.3', '192.168.1.5', '172.16.9.9', '127.0.0.1']) {
      expect(isReportable(ip, good, BAR, NOW).reportable).toBe(false);
    }
  });

  it('NEVER reports CGNAT / carrier (100.64/10)', () => {
    expect(isReportable('100.64.3.4', good, BAR, NOW).reportable).toBe(false);
  });

  it('NEVER reports reserved / documentation ranges', () => {
    for (const ip of ['203.0.113.5', '198.51.100.9', '192.0.2.1']) {
      expect(isReportable(ip, good, BAR, NOW).reportable).toBe(false);
    }
  });

  it('NEVER reports a spoofable (no completed handshake) source, however many signals', () => {
    const spoofable = summarizeEvidence([
      ev('network', 'synflood', 7_200_000),
      ev('scan', 'port-scan', 7_100_000),
      ev('network', 'udp-flood', 7_000_000),
    ]);
    const d = isReportable('8.8.4.4', spoofable, { ...BAR, neverReport: [] }, NOW);
    expect(d.reportable).toBe(false);
    expect(d.reason).toMatch(/spoofable/);
  });

  it('needs enough corroborating signals', () => {
    const thin = summarizeEvidence([ev('web', 'rule-engine', 7_200_000)]);
    const d = isReportable('8.8.4.4', thin, { ...BAR, neverReport: [] }, NOW);
    expect(d.reportable).toBe(false);
    expect(d.reason).toMatch(/corroborating/);
  });

  it('holds a source inside the cooling-off window', () => {
    const fresh = summarizeEvidence([ev('web', 'rule-engine', 60_000), ev('auth', 'ssh-guard', 30_000)]);
    const d = isReportable('8.8.4.4', fresh, { ...BAR, neverReport: [] }, NOW);
    expect(d.reportable).toBe(false);
    expect(d.waitSeconds).toBeGreaterThan(0);
  });

  it('rejects non-IP input', () => {
    expect(isReportable('not-an-ip', good, BAR, NOW).reportable).toBe(false);
  });
});

describe('abuseipdbCategories', () => {
  it('maps auth to brute-force + SSH', () => {
    expect(abuseipdbCategories(summarizeEvidence([ev('auth', 'ssh-guard', 1)]))).toContain(18);
    expect(abuseipdbCategories(summarizeEvidence([ev('auth', 'ssh-guard', 1)]))).toContain(22);
  });

  it('maps web to web-app attack and SQLi rules to 16', () => {
    const cats = abuseipdbCategories(summarizeEvidence([ev('web', 'rule-engine', 1, 'crs-942-sqli')]));
    expect(cats).toContain(21);
    expect(cats).toContain(16);
  });

  it('falls back to Hacking (15) when nothing specific matches', () => {
    expect(abuseipdbCategories(summarizeEvidence([ev('system', 'misc', 1)]))).toEqual([15]);
  });
});

describe('buildComment — redaction (R8)', () => {
  it('never carries our hostnames, paths or usernames from the raw message', () => {
    const comment = buildComment(summarizeEvidence([ev('web', 'rule-engine', 7_200_000), ev('auth', 'ssh-guard', 60_000)]));
    expect(comment).not.toMatch(/login\.php|user=root|nginx|\/admin/);
    expect(comment).toMatch(/ThreatCrush/);
    expect(comment).toMatch(/\d+ malicious/);
  });
});

describe('resolveConfig', () => {
  it('is enabled and live by default', () => {
    const c = resolveConfig(undefined);
    expect(c.enabled).toBe(true);
    expect(c.dryRun).toBe(false);
    expect(c.destinations).toEqual(['abuseipdb']);
    expect(c.minCorroboratingSignals).toBe(2);
  });

  it('honours dry_run mode and the never_report additions', () => {
    const c = resolveConfig({ mode: 'dry_run', never_report: ['5.5.5.0/24'] });
    expect(c.dryRun).toBe(true);
    expect(c.neverReport).toContain('5.5.5.0/24');
    expect(c.neverReport).toContain('100.64.0.0/10');
  });
});
