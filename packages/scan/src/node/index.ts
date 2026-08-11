/**
 * `@threatcrush/scan/node` — the parts that need a filesystem.
 *
 * Kept apart from the default entry point so that importing the rules does not
 * drag `node:fs` into a browser bundle. Import from here only where a real
 * filesystem exists: the CLI, the daemon, a server route.
 */

export { scanPath } from './walk.js';
export type { ScanOptions, ScanReport } from './walk.js';

export { scanDependencies } from './dependencies.js';

export { buildSarif, fingerprintOf, sarifLevel, securitySeverity, toArtifactUri } from './sarif.js';
export type { SarifOptions } from './sarif.js';
