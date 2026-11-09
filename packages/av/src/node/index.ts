/** `@threatcrush/av/node` — the parts of CrushAV that need a filesystem. */
export { fullScanTargets, quickScanTargets } from './locations';
export type { ScanTarget } from './locations';
export { SKIP_DIR_NAMES, walkFiles, walkTargets } from './walk';
export type { WalkFilesOptions } from './walk';
export { scanFileSync } from './scan-file';
export type { FileOutcome } from './scan-file';
export { runScanWorker } from './scan-worker';
export type { ScanWorkerInit } from './scan-worker';
export { clamDetection, clamInstallHint, clamScanFiles, detectClamAV, findBinary, parseClamOutput } from './clamav';
export type { ClamInfo } from './clamav';
export { deleteQuarantined, listQuarantine, quarantineDir, quarantineFile, restoreQuarantined } from './quarantine';
export type { QuarantineEntry } from './quarantine';
export { readForScan, scanPaths } from './scan';
export { watchTargets } from './watch';
export type { WatchOptions } from './watch';
export type { ScanPathsOptions, ScanProgress, ScanReport } from './scan';
