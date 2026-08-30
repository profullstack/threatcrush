import { defineConfig } from 'tsup';
import { cpSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    daemon: 'src/daemon-entry.ts',
  },
  format: ['cjs'],
  target: 'node20',
  platform: 'node',
  outDir: 'dist',
  clean: true,
  splitting: false,
  sourcemap: true,
  dts: false,

  external: ['better-sqlite3'],
  // `@threatcrush/scan` is bundled, not externalised. It resolves to
  // TypeScript source rather than a build output — see its package.json — so
  // there is nothing for Node to require at runtime, and the published CLI
  // must not gain a dependency on a package that is not published.
  // `@profullstack/hqtui` is ESM-only and this bundle is CJS, so a plain
  // `require` of it would throw ERR_REQUIRE_ESM at runtime. It has zero
  // runtime dependencies and imports no node builtins, so bundling it in is
  // both safe and what keeps the published CLI dependency-light.
  noExternal: ['chalk', 'ora', '@iarna/toml', 'commander', '@threatcrush/scan', '@profullstack/hqtui'],

  async onSuccess() {
    // Ship the systemd unit template alongside the compiled bundle.
    const src = join(__dirname, 'src', 'systemd', 'threatcrushd.service');
    const destDir = join(__dirname, 'dist', 'systemd');
    if (existsSync(src)) {
      mkdirSync(destDir, { recursive: true });
      cpSync(src, join(destDir, 'threatcrushd.service'));
    }
  },
});
