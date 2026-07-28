import { describe, expect, it } from 'vitest';
import {
  compareVersions,
  fixedVersionFor,
  isVersionAffected,
  parseVersion,
} from '../semver.js';

/**
 * Version comparison is the load-bearing primitive: every advisory match runs
 * through it, and a wrong answer is a silent false negative — the failure mode
 * this module exists to prevent. The prerelease rules are where hand-rolled
 * implementations usually break, so they are tested against semver 2.0.0 §11
 * directly rather than by example.
 */
describe('parseVersion', () => {
  it('accepts partial and prefixed versions', () => {
    expect(parseVersion('1')).toMatchObject({ major: 1, minor: 0, patch: 0 });
    expect(parseVersion('v2.3')).toMatchObject({ major: 2, minor: 3, patch: 0 });
    expect(parseVersion('1.2.3+build.5')).toMatchObject({ major: 1, minor: 2, patch: 3 });
  });

  it('splits prerelease identifiers, keeping numerics numeric', () => {
    expect(parseVersion('1.0.0-rc.1')?.prerelease).toEqual(['rc', 1]);
    expect(parseVersion('1.0.0-alpha.beta')?.prerelease).toEqual(['alpha', 'beta']);
  });

  it('returns null rather than throwing on non-semver input', () => {
    // Debian epochs, Go pseudo-versions and dist-tags all reach this code.
    expect(parseVersion('latest')).toBeNull();
    expect(parseVersion('1:2.3-4')).toBeNull();
  });
});

describe('compareVersions', () => {
  it('orders by major, minor, patch', () => {
    expect(compareVersions('1.0.0', '2.0.0')).toBe(-1);
    expect(compareVersions('1.2.0', '1.10.0')).toBe(-1); // not string order
    expect(compareVersions('1.0.1', '1.0.1')).toBe(0);
  });

  it('sorts a prerelease below its release', () => {
    // The rule that matters most: 1.0.0-rc.1 is NOT yet 1.0.0, so an advisory
    // "introduced in 1.0.0" must not match it.
    expect(compareVersions('1.0.0-rc.1', '1.0.0')).toBe(-1);
    expect(compareVersions('1.0.0', '1.0.0-rc.1')).toBe(1);
  });

  it('follows semver 2.0.0 §11 precedence for prereleases', () => {
    expect(compareVersions('1.0.0-alpha', '1.0.0-alpha.1')).toBe(-1); // more fields wins
    expect(compareVersions('1.0.0-alpha.1', '1.0.0-alpha.beta')).toBe(-1); // numeric < alpha
    expect(compareVersions('1.0.0-alpha.beta', '1.0.0-beta')).toBe(-1);
    expect(compareVersions('1.0.0-beta.2', '1.0.0-beta.11')).toBe(-1); // numeric, not lexical
    expect(compareVersions('1.0.0-rc.1', '1.0.0-beta.11')).toBe(1);
  });
});

describe('isVersionAffected', () => {
  it('treats introduced:0 as "from the beginning"', () => {
    const range = { events: [{ introduced: '0' }, { fixed: '4.17.21' }] };
    expect(isVersionAffected('4.17.20', range)).toBe(true);
    expect(isVersionAffected('4.17.21', range)).toBe(false); // fixed is exclusive
    expect(isVersionAffected('5.0.0', range)).toBe(false);
  });

  it('honours last_affected as an inclusive bound', () => {
    const range = { events: [{ introduced: '1.0.0' }, { last_affected: '1.5.0' }] };
    expect(isVersionAffected('1.5.0', range)).toBe(true);
    expect(isVersionAffected('1.5.1', range)).toBe(false);
  });

  it('handles reopened ranges across multiple majors', () => {
    const range = {
      events: [
        { introduced: '1.0.0' },
        { fixed: '1.9.0' },
        { introduced: '2.0.0' },
        { fixed: '2.1.0' },
      ],
    };
    expect(isVersionAffected('1.5.0', range)).toBe(true);
    expect(isVersionAffected('1.9.0', range)).toBe(false);
    expect(isVersionAffected('2.0.5', range)).toBe(true);
    expect(isVersionAffected('2.1.0', range)).toBe(false);
  });

  it('tolerates unsorted events', () => {
    // OSV records in the wild are not reliably ordered; reading them
    // positionally produces silent false negatives.
    const range = {
      events: [{ fixed: '2.1.0' }, { introduced: '2.0.0' }, { introduced: '0' }, { fixed: '1.9.0' }],
    };
    expect(isVersionAffected('1.0.0', range)).toBe(true);
    expect(isVersionAffected('1.9.5', range)).toBe(false);
    expect(isVersionAffected('2.0.1', range)).toBe(true);
  });

  it('reports nothing for an empty range rather than everything', () => {
    expect(isVersionAffected('1.0.0', { events: [] })).toBe(false);
  });
});

describe('fixedVersionFor', () => {
  it('returns the lowest fix above the installed version', () => {
    const ranges = [
      { events: [{ introduced: '0' }, { fixed: '1.9.0' }] },
      { events: [{ introduced: '2.0.0' }, { fixed: '2.1.0' }] },
    ];
    expect(fixedVersionFor('1.0.0', ranges)).toBe('1.9.0');
    expect(fixedVersionFor('2.0.0', ranges)).toBe('2.1.0');
  });

  it('returns null when the advisory names no fix', () => {
    expect(fixedVersionFor('1.0.0', [{ events: [{ introduced: '0' }] }])).toBeNull();
  });
});
