import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  buildInventory,
  expandWorkspaceGlobs,
  inventoryRoot,
  parsePackageLock,
  readWorkspacePatterns,
} from '../inventory.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'dep-scanner-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function write(relative: string, contents: unknown): Promise<void> {
  const path = join(dir, relative);
  await mkdir(join(path, '..'), { recursive: true });
  await writeFile(path, typeof contents === 'string' ? contents : JSON.stringify(contents));
}

/**
 * THE REGRESSION TEST.
 *
 * PRD 0002 names this permanently: a general-purpose analyzer pointed at a
 * 13-package pnpm workspace reported "0 direct dependencies, coupling 0/100
 * (low - good)" because it read only the root manifest and never resolved
 * `pnpm-workspace.yaml`. It found nothing and called the nothing *good*.
 *
 * A scanner that does this issues a clean bill of health without an
 * examination. If this test ever passes with an empty package list, the module
 * has regressed into that tool.
 */
describe('pnpm workspace resolution (PRD 0002 reference failure)', () => {
  beforeEach(async () => {
    await write('package.json', { name: 'root', private: true, devDependencies: { tsup: '^8.5.1' } });
    await write('pnpm-workspace.yaml', 'packages:\n  - "apps/*"\n  - "packages/*"\n');
    await write('apps/game/package.json', {
      name: '@x/game',
      dependencies: { '@babylonjs/core': '^7.0.0' },
    });
    await write('apps/site/package.json', {
      name: '@x/site',
      dependencies: { preact: '^10.0.0' },
      devDependencies: { vite: '^5.0.0' },
    });
    await write('packages/sim/package.json', {
      name: '@x/sim',
      dependencies: { colyseus: '^0.15.0' },
    });
  });

  it('finds dependencies declared in workspace members, not just the root', async () => {
    const report = await inventoryRoot(dir);
    const names = report.packages.map((p) => p.name);

    // The exact bug: reading only the root would yield tsup and nothing else.
    expect(names).toContain('@babylonjs/core');
    expect(names).toContain('preact');
    expect(names).toContain('colyseus');
    expect(report.manifests).toBe(4); // root + three members
    expect(report.packages.length).toBeGreaterThan(1);
  });

  it('never reports an empty workspace as a clean parse', async () => {
    const report = await inventoryRoot(dir);
    // No lockfile and no node_modules here, so this is honestly incomplete.
    expect(report.status).not.toBe('parsed');
    expect(report.reason).toBeTruthy();
  });

  it('marks dev-only dependencies without dropping them', async () => {
    const report = await inventoryRoot(dir);
    const vite = report.packages.find((p) => p.name === 'vite');
    expect(vite?.dev).toBe(true);
  });
});

describe('readWorkspacePatterns', () => {
  it('reads pnpm-workspace.yaml list items', async () => {
    await write('package.json', { name: 'r' });
    await write('pnpm-workspace.yaml', 'packages:\n  - "apps/*"\n  - "tools/one"\n');
    expect(await readWorkspacePatterns(dir)).toEqual(['"apps/*"', '"tools/one"']);
  });

  it('reads npm/yarn workspaces from package.json', async () => {
    await write('package.json', { name: 'r', workspaces: ['packages/*'] });
    expect(await readWorkspacePatterns(dir)).toEqual(['packages/*']);
  });

  it('reads the object form of workspaces', async () => {
    await write('package.json', { name: 'r', workspaces: { packages: ['libs/*'] } });
    expect(await readWorkspacePatterns(dir)).toEqual(['libs/*']);
  });
});

describe('expandWorkspaceGlobs', () => {
  beforeEach(async () => {
    await write('packages/a/package.json', { name: 'a' });
    await write('packages/b/package.json', { name: 'b' });
    await write('packages/not-a-package/readme.md', 'x');
  });

  it('expands a trailing star to directories that hold a manifest', async () => {
    const { dirs } = await expandWorkspaceGlobs(dir, ['packages/*']);
    expect(dirs).toHaveLength(2);
  });

  it('treats ** the same as * for workspace purposes', async () => {
    const { dirs } = await expandWorkspaceGlobs(dir, ['packages/**']);
    expect(dirs).toHaveLength(2);
  });

  it('strips quotes left by the YAML scrape', async () => {
    const { dirs } = await expandWorkspaceGlobs(dir, ['"packages/*"']);
    expect(dirs).toHaveLength(2);
  });

  it('reports patterns it could not resolve instead of dropping them', async () => {
    const { dirs, unresolved } = await expandWorkspaceGlobs(dir, ['nope/*']);
    expect(dirs).toHaveLength(0);
    expect(unresolved).toEqual(['nope/*']);
  });

  it('ignores negations', async () => {
    const { dirs } = await expandWorkspaceGlobs(dir, ['!packages/a']);
    expect(dirs).toHaveLength(0);
  });
});

describe('parsePackageLock', () => {
  it('reads lockfileVersion 3 and distinguishes direct from transitive', () => {
    const records = parsePackageLock({
      lockfileVersion: 3,
      packages: {
        '': { version: '1.0.0' },
        'node_modules/lodash': { version: '4.17.20' },
        'node_modules/ws': { version: '7.4.6', dev: true },
        'node_modules/a/node_modules/b': { version: '2.0.0' },
        'packages/member': { version: '1.0.0', link: true },
      },
    });

    expect(records.find((r) => r.name === 'lodash')).toMatchObject({
      version: '4.17.20',
      direct: true,
    });
    expect(records.find((r) => r.name === 'ws')?.dev).toBe(true);
    expect(records.find((r) => r.name === 'b')?.direct).toBe(false);
    // Workspace links are covered by their own manifest, not as dependencies.
    expect(records.some((r) => r.name === 'member')).toBe(false);
  });

  it('falls back to the v1 dependencies map', () => {
    const records = parsePackageLock({
      lockfileVersion: 1,
      dependencies: { lodash: { version: '4.17.20' } },
    });
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ name: 'lodash', version: '4.17.20' });
  });
});

describe('honest failure reporting', () => {
  it('marks Yarn PnP as failed rather than silently empty', async () => {
    await write('package.json', { name: 'pnp-app' });
    await write('.pnp.cjs', '/* pnp */');

    const report = await inventoryRoot(dir);
    expect(report.status).toBe('failed');
    expect(report.reason).toMatch(/PnP/i);
    expect(report.packages).toHaveLength(0);
  });

  it('marks an unparseable manifest as failed', async () => {
    await write('package.json', '{ not json');
    const report = await inventoryRoot(dir);
    expect(report.status).toBe('failed');
  });

  it('flags the whole inventory incomplete when any root failed', async () => {
    await write('good/package.json', { name: 'good', dependencies: { lodash: '4.17.21' } });
    await write('bad/package.json', '{ broken');

    const inventory = await buildInventory([dir]);
    expect(inventory.incomplete).toBe(true);
    expect(inventory.roots.some((r) => r.status === 'failed')).toBe(true);
  });
});

describe('installed-vs-locked drift', () => {
  it('reports a package on disk that disagrees with the lockfile', async () => {
    await write('package.json', { name: 'app', dependencies: { lodash: '^4.17.21' } });
    await write('package-lock.json', {
      lockfileVersion: 3,
      packages: { '': { version: '1.0.0' }, 'node_modules/lodash': { version: '4.17.21' } },
    });
    // A hand-applied hotfix at 2am, or an attacker.
    await write('node_modules/lodash/package.json', { name: 'lodash', version: '4.17.19' });

    const report = await inventoryRoot(dir);
    expect(report.drift).toEqual([
      { name: 'lodash', locked: '4.17.21', installed: '4.17.19' },
    ]);
  });

  it('stays quiet when disk and lockfile agree', async () => {
    await write('package.json', { name: 'app', dependencies: { lodash: '^4.17.21' } });
    await write('package-lock.json', {
      lockfileVersion: 3,
      packages: { '': { version: '1.0.0' }, 'node_modules/lodash': { version: '4.17.21' } },
    });
    await write('node_modules/lodash/package.json', { name: 'lodash', version: '4.17.21' });

    const report = await inventoryRoot(dir);
    expect(report.drift).toHaveLength(0);
  });
});
