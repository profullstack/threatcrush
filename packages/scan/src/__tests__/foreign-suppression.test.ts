import { describe, expect, it } from 'vitest';
import { foreignCredentialMark, scanText } from '../text';

// Copied from thecodearcher/limen, where these two lines were reported as high
// with the annotation visible in the excerpt.
const HEADERS = [
  'const (',
  '\tHeaderSetAuthToken    = "Set-Auth-Token"    //nolint:gosec // G101 false positive: HTTP header name, not a credential',
  '\tHeaderSetRefreshToken = "Set-Refresh-Token" //nolint:gosec // G101 false positive: HTTP header name, not a credential',
  ')',
].join('\n');

describe('a line another linter was already told about', () => {
  it('reads a gosec G101 annotation, in either order', () => {
    expect(foreignCredentialMark('x = "y" //nolint:gosec // G101 false positive')).toBe(true);
    expect(foreignCredentialMark('x = "y" // #nosec G101 -- header name')).toBe(true);
    expect(foreignCredentialMark('x = "y" // G101 handled: #nosec')).toBe(true);
  });

  // A bare `//nolint` is a statement about something, and there is no reason to
  // think it is about credentials.
  it('takes no notice of an annotation that names no rule', () => {
    expect(foreignCredentialMark('x = "y" //nolint')).toBe(false);
    expect(foreignCredentialMark('x = "y" //nolint:errcheck')).toBe(false);
    expect(foreignCredentialMark('x = "y" //nolint:gosec')).toBe(false);
    expect(foreignCredentialMark('x = "y" // G101')).toBe(false);
  });

  it('drops the annotated finding to low rather than out of the report', () => {
    const findings = scanText('response.go', HEADERS).filter((one) => one.category === 'secret');

    expect(findings.length).toBeGreaterThan(0);
    for (const one of findings) {
      expect(one.severity).toBe('low');
      expect(one.message).toContain('already marked as a false positive');
    }
  });

  it('leaves an unannotated credential on the same file at its own severity', () => {
    const source = `${HEADERS}\nconst apiKey = "sk_live_51H8xQ2KZvKuT9mNpR4wXyZ"\n`;
    const loud = scanText('response.go', source).filter((one) => one.severity !== 'low');

    expect(loud.length).toBeGreaterThan(0);
  });
});
