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

  external: ['better-sqlite3', 'blessed', 'blessed-contrib', 'react', 'react-blessed', 'react-blessed-contrib'],
  noExternal: ['chalk', 'ora', '@iarna/toml', 'commander'],

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
