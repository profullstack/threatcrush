import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs'],
  target: 'node20',
  platform: 'node',
  outDir: 'dist',
  clean: true,
  splitting: false,
  sourcemap: true,
  dts: false,

  external: ['better-sqlite3', 'blessed', 'blessed-contrib'],
  noExternal: ['chalk', 'ora', '@iarna/toml', 'commander'],
});
