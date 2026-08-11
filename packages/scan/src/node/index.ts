/**
 * `@threatcrush/scan/node` — the parts that need a filesystem.
 *
 * Kept apart from the default entry point so that importing the rules does not
 * drag `node:fs` into a browser bundle. Import from here only where a real
 * filesystem exists: the CLI, the daemon, a server route.
 */

export { scanPath } from './walk';
export type { ScanOptions, ScanReport } from './walk';

export { scanDependencies } from './dependencies';

export { buildSarif, fingerprintOf, sarifLevel, securitySeverity, toArtifactUri } from './sarif';
export type { SarifOptions } from './sarif';
