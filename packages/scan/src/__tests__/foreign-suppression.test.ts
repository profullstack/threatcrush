import { describe, expect, it } from 'vitest';
import { foreignSecurityMark, scanText } from '../text';

// Copied from thecodearcher/limen, where these two lines were reported as high
// with the annotation visible in the excerpt.
const HEADERS = [
  'const (',
  '\tHeaderSetAuthToken    = "Set-Auth-Token"    //nolint:gosec // G101 false positive: HTTP header name, not a credential',
  '\tHeaderSetRefreshToken = "Set-Refresh-Token" //nolint:gosec // G101 false positive: HTTP header name, not a credential',
  ')',
].join('\n');

// Copied from mulgadc/spinifex, which writes the form Go projects actually
// write: the linter named, the rule not, and the reason in English beside it.
const TRANSPORT = [
  'func probe() *http.Client {',
  '\treturn &http.Client{Transport: &http.Transport{',
  '\t\tTLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed per-node certs',
  '\t}}',
  '}',
].join('\n');

describe('a line another linter was already told about', () => {
  it('reads a gosec annotation, with or without the rule number', () => {
    expect(foreignSecurityMark('x = "y" //nolint:gosec // G101 false positive')).toBe(true);
    expect(foreignSecurityMark('x = "y" // #nosec G101 -- header name')).toBe(true);
    expect(foreignSecurityMark('x = "y" // G101 handled: #nosec')).toBe(true);
    // The bare form. Requiring `G101` alongside it meant honouring the
    // annotation almost nowhere it is written — nine of spinifex's twenty-one
    // `InsecureSkipVerify` lines carry exactly this and were reported anyway.
    expect(foreignSecurityMark('x = "y" //nolint:gosec')).toBe(true);
    expect(foreignSecurityMark('x = "y" //nolint:gosec,govet // reason')).toBe(true);
  });

  // Naming the *linter* is what keeps this from being a way to hide findings.
  // A bare `//nolint` is a statement about something, with no reason to think
  // it is about security; `errcheck` is a statement about error handling.
  it('takes no notice of an annotation that names no security linter', () => {
    expect(foreignSecurityMark('x = "y" //nolint')).toBe(false);
    expect(foreignSecurityMark('x = "y" //nolint:errcheck')).toBe(false);
    expect(foreignSecurityMark('x = "y" // G101')).toBe(false);
  });

  it('drops the annotated credential to low rather than out of the report', () => {
    const findings = scanText('response.go', HEADERS).filter((one) => one.category === 'secret');

    expect(findings.length).toBeGreaterThan(0);
    for (const one of findings) {
      expect(one.severity).toBe('low');
      expect(one.message).toContain('already marked as a false positive');
    }
  });

  // The same courtesy for the code rules, which never read the annotation at
  // all until now. `tls-verification-disabled` is `inherent`, so it reports at
  // high on evidence and nothing in the surrounding lines could soften it.
  it('drops an annotated code finding to low rather than out of the report', () => {
    const findings = scanText('daemon.go', TRANSPORT).filter(
      (one) => one.ruleId === 'tls-verification-disabled',
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('low');
    expect(findings[0]!.message).toContain("another linter's security suppression");
  });

  it('leaves the same construct at full severity with no annotation', () => {
    const findings = scanText('daemon.go', TRANSPORT.replace(' //nolint:gosec // self-signed per-node certs', '')).filter(
      (one) => one.ruleId === 'tls-verification-disabled',
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high');
  });

  // Assembled rather than written out. A file in this repository that carries a
  // string shaped like an issued key is a finding for every other scanner that
  // reads us, and one of them gates our own CI.
  const issued = ['sk', 'live', '51H8xQ2KZvKuT9mNpR4wXyZ'].join('_');

  it('leaves an unannotated credential on the same file at its own severity', () => {
    const source = `${HEADERS}\nconst apiKey = "${issued}"\n`;
    const loud = scanText('response.go', source).filter((one) => one.severity !== 'low');

    expect(loud.length).toBeGreaterThan(0);
  });
});
