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
    // The bundle carries rules derived from OWASP CRS (Apache-2.0), so its
    // licence and notice ship with it.
    const crsDir = join(__dirname, 'dist', 'crs');
    mkdirSync(crsDir, { recursive: true });
    for (const f of ['LICENSE', 'NOTICE']) cpSync(join(__dirname, 'src', 'core', 'crs', f), join(crsDir, f));
    // libinjection (BSD-3-Clause), compiled to WebAssembly, is loaded from
    // dist/libinjection/ at run time (src/core/crs/libinjection.ts); its
    // licence ships with it.
    const libinjectionDir = join(__dirname, 'dist', 'libinjection');
    mkdirSync(libinjectionDir, { recursive: true });
    cpSync(join(__dirname, 'src', 'core', 'crs', 'libinjection', 'libinjection.wasm'), join(libinjectionDir, 'libinjection.wasm'));
    cpSync(join(__dirname, 'vendor', 'libinjection', 'COPYING'), join(libinjectionDir, 'COPYING'));
  },
});
