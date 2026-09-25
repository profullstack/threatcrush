import { defineConfig } from 'vitest/config';

// Store/unit tests run in plain Node. Native modules (expo-*, react-native) are
// replaced in src/__tests__/setup.ts; the network is stubbed per test at fetch.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/__tests__/**/*.test.ts'],
    setupFiles: ['./src/__tests__/setup.ts'],
  },
});
