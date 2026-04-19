// web-ext configuration
// https://extensionworkshop.com/documentation/develop/web-ext-command-reference/#web-ext-config-js

export default {
  sourceDir: './dist/firefox',
  ignoreFiles: [
    'scripts/**',
    'src/**',
    '__tests__/**',
    'node_modules/**',
    '*.config.js',
    '*.config.mjs',
    'package.json',
    'pnpm-lock.yaml',
    '.env*',
    'vitest.setup.js',
  ],
};
