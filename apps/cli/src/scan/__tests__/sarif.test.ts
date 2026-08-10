import { describe, expect, it } from 'vitest';
import { buildSarif, fingerprintOf, sarifLevel, securitySeverity, toArtifactUri } from '../sarif.js';
import type { ScanFinding } from '../types.js';

const finding = (overrides: Partial<ScanFinding> = {}): ScanFinding => ({
  ruleId: 'secret-aws-access-key',
  title: 'AWS Access Key',
  file: 'secrets/creds.env',
  line: 23,
  severity: 'critical',
  confidence: 'evidence',
  message: 'Possible AWS Access Key detected',
  consequence: 'Grants the API access of the issuing IAM principal.',
  cwe: 'CWE-798',
  excerpt: 'AWS_ACCESS_KEY_ID=AKI**************',
  category: 'secret',
  ...overrides,
});

const firstResult = (log: unknown): any => (log as any).runs[0].results[0];
const uriOf = (log: unknown): string =>
  firstResult(log).locations[0].physicalLocation.artifactLocation.uri;

/**
 * `primaryLocationLineHash` is a key GitHub reserves and recomputes. It used to
 * carry `ruleId:file:line`, which GitHub rejected as inconsistent on every
 * upload and which changed whenever code above the finding moved — so dismissed
 * alerts came back and review comments detached.
 */
describe('fingerprints', () => {
  it('is a hash, not a readable triple', () => {
    const value = fingerprintOf(finding());
    expect(value).toMatch(/^[0-9a-f]{32}$/);
    expect(value).not.toContain('secret-aws-access-key');
    expect(value).not.toContain('23');
  });

  it('survives the finding moving to another line', () => {
    expect(fingerprintOf(finding({ line: 23 }))).toBe(fingerprintOf(finding({ line: 891 })));
  });

  it('survives reindentation', () => {
    const a = finding({ excerpt: 'foo(bar)' });
    const b = finding({ excerpt: '      foo(bar)  ' });
    expect(fingerprintOf(a)).toBe(fingerprintOf(b));
  });

  it('separates different rules, files and content', () => {
    const base = fingerprintOf(finding());
    expect(fingerprintOf(finding({ ruleId: 'secret-github-token' }))).not.toBe(base);
    expect(fingerprintOf(finding({ file: 'other/creds.env' }))).not.toBe(base);
    expect(fingerprintOf(finding({ excerpt: 'something else' }))).not.toBe(base);
  });

  it('is published under a namespaced key, not the reserved one', () => {
    // `primaryLocationLineHash` is computed by GitHub's upload action, which
    // logs an inconsistent-fingerprint warning for every finding when we also
    // supply it — whatever value we put there.
    const f = finding();
    const log = buildSarif([f], { toolVersion: '1.0.0', base: '/repo', root: '/repo' });
    const prints = firstResult(log).partialFingerprints;
    expect(prints['threatcrush/contentHash/v1']).toBe(fingerprintOf(f));
    expect(prints).not.toHaveProperty('primaryLocationLineHash');
  });
});

describe('artifact URIs', () => {
  it('resolves finding paths against the scan root, not the working directory', () => {
    // The bug this guards: findings carry paths relative to the scan root, so
    // scanning `vulns/` from a repo root emitted `secrets/x.env`. Every
    // consumer scoped to the repository then reported the finding as
    // out-of-corpus, and a working scan read as 0% coverage.
    expect(toArtifactUri('secrets/x.env', '/repo', '', '/repo/vulns')).toBe('vulns/secrets/x.env');
  });

  it('applies an explicit prefix for scans run from inside the target', () => {
    expect(toArtifactUri('secrets/x.env', '/repo/vulns', 'vulns', '/repo/vulns')).toBe(
      'vulns/secrets/x.env',
    );
  });

  it('emits POSIX separators and no leading ./', () => {
    expect(toArtifactUri('a/b/c.js', '/repo', '', '/repo')).toBe('a/b/c.js');
  });

  it('keeps an absolute path rather than a run of ../ segments', () => {
    expect(toArtifactUri('/elsewhere/x.js', '/repo', 'vulns', '/repo')).toBe('/elsewhere/x.js');
  });
});

describe('SARIF document', () => {
  it('is a valid 2.1.0 run with a driver and rules', () => {
    const log = buildSarif([finding()], { toolVersion: '1.2.3', base: '/repo', root: '/repo' }) as any;
    expect(log.version).toBe('2.1.0');
    expect(log.runs).toHaveLength(1);
    expect(log.runs[0].tool.driver.name).toBe('ThreatCrush');
    expect(log.runs[0].tool.driver.version).toBe('1.2.3');
    expect(log.runs[0].tool.driver.rules[0].id).toBe('secret-aws-access-key');
  });

  it('clamps startLine to 1 — SARIF rejects 0', () => {
    // Whole-file findings have no line. Emitting 0 fails schema validation and
    // GitHub drops the whole upload rather than the one result.
    const log = buildSarif([finding({ line: 0 })], { toolVersion: '1.0.0', base: '/repo', root: '/repo' });
    expect(firstResult(log).locations[0].physicalLocation.region.startLine).toBe(1);
  });

  it('tags the CWE so consumers can group by weakness', () => {
    const log = buildSarif([finding()], { toolVersion: '1.0.0', base: '/repo', root: '/repo' }) as any;
    expect(log.runs[0].tool.driver.rules[0].properties.tags).toContain('external/cwe/cwe-798');
  });

  it('emits a valid empty run for a clean scan', () => {
    // Distinguishable from a missing file, which is the point: a consumer must
    // be able to tell "looked, found nothing" from "never ran".
    const log = buildSarif([], { toolVersion: '1.0.0', base: '/repo', root: '/repo' }) as any;
    expect(log.runs[0].results).toEqual([]);
    expect(log.runs[0].tool.driver.rules).toEqual([]);
  });

  it('maps severity onto SARIF levels and GitHub security-severity', () => {
    expect(sarifLevel('critical')).toBe('error');
    expect(sarifLevel('high')).toBe('error');
    expect(sarifLevel('medium')).toBe('warning');
    expect(sarifLevel('low')).toBe('note');
    expect(securitySeverity('critical')).toBe('9.0');
    expect(securitySeverity('medium')).toBe('5.0');
  });

  it('reports confidence as SARIF precision', () => {
    const log = buildSarif([finding({ confidence: 'pattern' })], {
      toolVersion: '1.0.0',
      base: '/repo',
      root: '/repo',
    }) as any;
    expect(log.runs[0].tool.driver.rules[0].properties.precision).toBe('medium');
  });

  it('does not carry raw credential material into the excerpt', () => {
    const log = buildSarif([finding()], { toolVersion: '1.0.0', base: '/repo', root: '/repo' });
    expect(firstResult(log).locations[0].physicalLocation.region.snippet.text).not.toMatch(
      /AKIA[0-9A-Z]{16}/,
    );
  });

  it('places the finding at the resolved URI', () => {
    const log = buildSarif([finding()], { toolVersion: '1.0.0', base: '/repo', root: '/repo/vulns' });
    expect(uriOf(log)).toBe('vulns/secrets/creds.env');
  });
});
