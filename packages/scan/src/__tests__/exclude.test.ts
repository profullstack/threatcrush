import { describe, expect, it } from 'vitest';
import { compileExcludes } from '../node/walk';

/**
 * The exclusion matcher decides which paths a scan skips, so a bug here either
 * hides real findings (over-matching) or defeats the feature (under-matching).
 * Both directions are pinned.
 */
describe('exclude globs', () => {
  const matches = (patterns: string[], path: string) => compileExcludes(patterns)(path);

  it('matches a bare name at any depth', () => {
    const p = ['__tests__'];
    expect(matches(p, 'packages/scan/src/__tests__/code-rules.test.ts')).toBe(true);
    expect(matches(p, '__tests__/a.ts')).toBe(true);
    expect(matches(p, 'src/__tests__')).toBe(true);
    // Not a substring: `__tests__helper` is a different name.
    expect(matches(p, 'src/__tests__helper/a.ts')).toBe(false);
  });

  it('anchors a pattern that contains a slash to the scan root', () => {
    const p = ['packages/scan/src/code-rules.ts'];
    expect(matches(p, 'packages/scan/src/code-rules.ts')).toBe(true);
    // Same basename elsewhere is not excluded — the slash anchored it.
    expect(matches(p, 'other/code-rules.ts')).toBe(false);
  });

  it('treats * as within-segment and ** as across-segments', () => {
    expect(matches(['*.test.ts'], 'packages/scan/src/__tests__/x.test.ts')).toBe(true);
    expect(matches(['*.test.ts'], 'x.spec.ts')).toBe(false);
    // `*` does not cross a slash.
    expect(matches(['packages/*/index.ts'], 'packages/scan/index.ts')).toBe(true);
    expect(matches(['packages/*/index.ts'], 'packages/scan/src/index.ts')).toBe(false);
    // `**` does.
    expect(matches(['modules/**/rules.ts'], 'modules/code-scanner/src/secrets/rules.ts')).toBe(true);
    expect(matches(['modules/**/rules.ts'], 'modules/rules.ts')).toBe(true);
  });

  it('prunes a whole subtree when the directory itself matches', () => {
    const p = ['packages/scan/src/__tests__'];
    expect(matches(p, 'packages/scan/src/__tests__')).toBe(true);
    expect(matches(p, 'packages/scan/src/__tests__/deep/a.ts')).toBe(true);
    expect(matches(p, 'packages/scan/src/text.ts')).toBe(false);
  });

  it('ignores blank lines and comments, so a .threatcrushignore passes straight in', () => {
    const file = ['# scanner self-reference', '', '  __tests__  ', '#another'];
    expect(matches(file, 'a/__tests__/b.ts')).toBe(true);
    expect(matches(file, 'a/b.ts')).toBe(false);
  });

  it('matches nothing when there are no real patterns', () => {
    const none = compileExcludes(['', '  ', '# just a comment']);
    expect(none('anything/at/all.ts')).toBe(false);
  });

  it('does not let a metacharacter in the pattern match literally', () => {
    // `.` in the pattern is a literal dot, not "any char".
    expect(matches(['config.ts'], 'configXts')).toBe(false);
    expect(matches(['config.ts'], 'config.ts')).toBe(true);
  });
});
