import { describe, expect, it } from 'vitest';
import { DEFAULT_RULES } from '../rules/default-rules.js';

const RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * A rule that declares `block` but sits below the default `min_severity`
 * (`high`) fires, logs, and bans nobody. web-scanner-detection and
 * port-scan-indicator were both `medium`: on dev1 they detected 46 scans
 * between them and banned none.
 */
describe('default rules that declare block', () => {
  const blocking = DEFAULT_RULES.filter((r) => r.remediation?.action === 'block');

  it('exist', () => {
    expect(blocking.length).toBeGreaterThan(0);
  });

  it.each(blocking.map((r) => [r.id, r.severity]))(
    '%s is at a severity the default floor bans (%s)',
    (_id, severity) => {
      expect(RANK[severity]).toBeGreaterThanOrEqual(RANK.high);
    },
  );
});
