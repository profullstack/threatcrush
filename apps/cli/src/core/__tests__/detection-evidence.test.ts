import { describe, expect, it } from 'vitest';
import { trimMetadata, MAX_METADATA_BYTES } from '../cloud-events.js';
import { RuleEngine, evidenceOf } from '../../daemon/rules/engine.js';

const bytes = (v: unknown) => Buffer.byteLength(JSON.stringify(v));

describe('detection evidence', () => {
  it('keeps the triggering line, a few named fields, and caps them', () => {
    const e = evidenceOf({
      timestamp: new Date('2026-10-28T17:23:56.606Z'), module: 'user-journal', category: 'system', severity: 'critical',
      message: 'sudo: pam_unix(sudo:auth): auth could not identify password for [anthony]', source_ip: '10.0.0.1',
      details: { unit: 'sudo', user: 'anthony', headers: { cookie: 'secret' }, huge: 'x'.repeat(10_000) },
    } as never);
    expect(e).toMatchObject({ at: '2026-10-28T17:23:56.606Z', module: 'user-journal', unit: 'sudo', user: 'anthony', source_ip: '10.0.0.1' });
    expect(e.message).toContain('could not identify password');
    expect(e).not.toHaveProperty('headers');
    expect(e).not.toHaveProperty('huge');
    expect(String(evidenceOf({ timestamp: new Date(), module: 'm', message: 'y'.repeat(2000), details: {} } as never).message).length).toBe(500);
  });

  it('the rule engine attaches it to every detection', () => {
    const fired: Array<{ raw_metadata?: Record<string, unknown> }> = [];
    const engine = new RuleEngine((d) => fired.push(d));
    engine.loadRules([{ id: 'crit', version: '1.0.0', title: 'Critical System Error', description: 'Critical log message', severity: 'critical',
      category: 'system', source_types: [], tags: ['system'], window_seconds: 60, threshold: 1, cooldown_seconds: 0, enabled: true,
      match: { field: 'message', operator: 'contains', value: 'Out of memory' } } as never]);
    engine.evaluate({ timestamp: new Date(), module: 'user-journal', category: 'system', severity: 'critical', message: 'kernel: Out of memory: Killed process 4242 (postgres)', details: {} } as never);
    expect(fired).toHaveLength(1);
    expect((fired[0].raw_metadata?.evidence as { message: string }).message).toBe('kernel: Out of memory: Killed process 4242 (postgres)');
  });
});

describe('trimMetadata', () => {
  it('shrinks an oversized value to an excerpt before dropping anything, and never drops evidence', () => {
    const big = Array.from({ length: 400 }, (_, i) => ({ i, line: 'z'.repeat(100) }));
    const out = trimMetadata({ tags: ['a'], remediation: big, extra: big, evidence: { message: 'the line that matters' } });
    expect(bytes(out)).toBeLessThanOrEqual(MAX_METADATA_BYTES);
    expect(out._truncated).toBe(true);
    expect(out.evidence).toEqual({ message: 'the line that matters' });
    expect(typeof out.remediation).toBe('string');
    expect(String(out.remediation).endsWith('…')).toBe(true);
  });

  it('leaves small metadata alone', () => {
    expect(trimMetadata({ tags: ['a'], evidence: { message: 'm' } })).toEqual({ tags: ['a'], evidence: { message: 'm' } });
  });
});
