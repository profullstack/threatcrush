import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The default entry point must stay free of `node:` imports.
 *
 * This is the whole reason the package is split the way it is. The web app,
 * the extension and the desktop renderer import `@threatcrush/scan` into a
 * browser bundle; a single `node:fs` anywhere in that module graph breaks all
 * of them, and it breaks at *their* build, not ours — which is the kind of
 * failure that gets found late and blamed on the wrong repository.
 *
 * A comment saying "do not import node: here" does not survive contact with a
 * hurried change. This does.
 */

const SRC = join(__dirname, '..');

function sourceFilesOutsideNodeEntry(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    // `node/` is the entry point that is *allowed* to touch the filesystem,
    // and `__tests__/` is this file and its neighbours — neither ships to a
    // browser.
    if (entry.isDirectory()) {
      if (entry.name === 'node' || entry.name === '__tests__') continue;
      sourceFilesOutsideNodeEntry(join(dir, entry.name), acc);
      continue;
    }
    if (entry.name.endsWith('.ts')) acc.push(join(dir, entry.name));
  }
  return acc;
}

describe('module boundaries', () => {
  const files = sourceFilesOutsideNodeEntry(SRC);

  it('finds the source files it is supposed to be checking', () => {
    // Guards the guard: a broken walk would make every assertion below pass
    // over an empty list.
    expect(files.length).toBeGreaterThanOrEqual(5);
  });

  it.each(files.map((f) => [f.slice(SRC.length + 1), f] as const))(
    '%s imports nothing from node:',
    (_label, file) => {
      const offending = readFileSync(file, 'utf-8')
        .split('\n')
        // Comment lines are skipped, because the first thing this test found
        // was the sentence in `text.ts` explaining why `node:fs` must not
        // appear there. Matching prose as if it were code is the exact bug the
        // scanner's own `proseLines` exists to avoid.
        .filter((line) => !/^\s*(?:\/\/|\/?\*)/.test(line))
        .filter((line) => /\bfrom\s+['"]node:/.test(line) || /\brequire\(\s*['"]node:/.test(line));
      expect(offending).toEqual([]);
    },
  );
});
