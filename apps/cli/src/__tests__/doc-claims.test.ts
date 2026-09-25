import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CRS_RULES } from '../core/crs/rules.generated.js';
import { DEFAULT_RULES } from '../daemon/rules/default-rules.js';

/**
 * Public copy once promised a four-digit signature count while the code loaded
 * a couple of dozen regexes. Every count the README, CLI README, landing page
 * and deck print must be the count the code actually loads — derived here,
 * never hand-typed.
 *
 * When the signature source changes, update `countAttackSignatures` and
 * `SIGNATURE_NOUN` (the phrase the copy uses) and nothing else.
 */
function countAttackSignatures(): number {
  return CRS_RULES.length;
}
const SIGNATURE_NOUN = 'OWASP CRS rules';
const RULE_NOUN = 'detection rules';

const REPO_ROOT = join(__dirname, '..', '..', '..', '..');
const CLAIM_FILES = [
  'README.md',
  'apps/cli/README.md',
  'apps/web/src/app/page.tsx',
  'apps/web/src/app/deck/page.tsx',
];

/** Every number written immediately before `noun`, e.g. "95 OWASP CRS rules" → 95. */
function claimedCounts(text: string, noun: string): number[] {
  const re = new RegExp(`(\\d[\\d,]*)\\s+${noun}`, 'gi');
  return [...text.matchAll(re)].map((m) => Number(m[1].replace(/,/g, '')));
}

describe('public copy matches what the code loads', () => {
  for (const file of CLAIM_FILES) {
    const text = readFileSync(join(REPO_ROOT, file), 'utf-8');

    it(`${file} states the real attack signature count`, () => {
      const claims = claimedCounts(text, SIGNATURE_NOUN);
      expect(claims.length, `${file} should say how many ${SIGNATURE_NOUN} ship`).toBeGreaterThan(0);
      for (const n of claims) expect(n).toBe(countAttackSignatures());
    });

    it(`${file} states the real detection rule count, if any`, () => {
      for (const n of claimedCounts(text, RULE_NOUN)) expect(n).toBe(DEFAULT_RULES.length);
    });
  }
});
