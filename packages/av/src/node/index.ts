/** `@threatcrush/av/node` — the parts of CrushAV that need a filesystem. */
export { fullScanTargets, quickScanTargets } from './locations';
export type { ScanTarget } from './locations';
export { SKIP_DIR_NAMES, walkTargets } from './walk';
export { clamDetection, clamInstallHint, clamScanFiles, detectClamAV, findBinary, parseClamOutput } from './clamav';
export type { ClamInfo } from './clamav';
export { deleteQuarantined, listQuarantine, quarantineDir, quarantineFile, restoreQuarantined } from './quarantine';
export type { QuarantineEntry } from './quarantine';
export { readForScan, scanPaths } from './scan';
export { watchTargets } from './watch';
export type { WatchOptions } from './watch';
export type { ScanPathsOptions, ScanProgress, ScanReport } from './scan';
