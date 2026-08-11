import { describe, expect, it } from 'vitest';
import { parseFailOn } from '../scan.js';

/**
 * Flag parsing lives here rather than with the engine tests.
 *
 * `@threatcrush/scan` decides what a finding is and whether a set of them
 * clears a threshold; it has no opinion about argv. This is the boundary the
 * package extraction drew, and the test placement follows it.
 */
describe('--fail-on', () => {
  it('accepts a comma-separated list of severities', () => {
    expect(parseFailOn('critical,high')).toEqual(['critical', 'high']);
  });

  it('rejects an unknown severity rather than silently ignoring it', () => {
    // Silently accepting `--fail-on hihg` produces a gate that never fires,
    // which looks exactly like a passing build.
    expect(() => parseFailOn('hihg')).toThrow(/unknown severity/);
  });
});
