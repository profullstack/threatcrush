import { defineConfig } from 'vitest/config';
import { resolve } from 'path';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'node',
    include: ['__tests__/**/*.test.js', '__tests__/**/*.test.jsx'],
    globals: true,
    environmentMatchGlobs: [
      // Use jsdom for React component tests
      ['__tests__/**/*.test.jsx', 'jsdom'],
    ],
    setupFiles: ['./vitest.setup.js'],
  },
  resolve: {
    alias: {
      '@': resolve(import.meta.dirname, 'src'),
    },
  },
});
