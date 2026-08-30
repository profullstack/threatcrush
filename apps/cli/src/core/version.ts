import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// The bundles live in `dist/`, which sits at the package root once published,
// so the manifest is always one level up from `__dirname`. Reading it keeps the
// version in one place: a hardcoded literal reports whatever it was written at,
// no matter which release is actually installed.
const FALLBACK_VERSION = '0.0.0';

function readPackageVersion(): string {
  try {
    const pkg = JSON.parse(
      readFileSync(join(__dirname, '..', 'package.json'), 'utf-8'),
    ) as { version?: string };
    return pkg.version || FALLBACK_VERSION;
  } catch {
    return FALLBACK_VERSION;
  }
}

export const PKG_VERSION = readPackageVersion();
