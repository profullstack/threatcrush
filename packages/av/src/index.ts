/**
 * `@threatcrush/av` — CrushAV, the free open-source ThreatCrush antivirus.
 *
 * This entry point has no `node:` imports: it runs in Node, Electron, a
 * browser tab and React Native alike, so every surface shares one engine.
 * Filesystem work (walking folders, ClamAV, quarantine) lives in
 * `@threatcrush/av/node`.
 */

export type { AvDetection, AvEngine, AvFileResult, AvSeverity, AvSummary, AvVerdict, FileKind, HashReputation } from './types';
export { Sha256, sha256Hex, SHA256_RE } from './sha256';
export { baseName, DOCUMENT_EXTENSIONS, EXECUTABLE_KINDS, extOf, RUNNABLE_EXTENSIONS, sniffKind } from './magic';
export { buildContext, EICAR, RULES, runRules } from './rules';
export type { AvRule, RuleContext } from './rules';
export {
  applyReputation,
  BUILTIN_SIGNATURES,
  DEFAULT_HEURISTIC_BYTES,
  scanBytes,
  SignatureSet,
  TRUSTED_SCORE,
  verdictOf,
} from './engine';
export type { ScanBytesInput, ScanBytesOptions } from './engine';
export {
  DEFAULT_LOOKUP_ENDPOINT,
  lookupHashes,
  LOOKUP_BATCH,
  mergeReputation,
  queryCircl,
  queryMalwareBazaar,
} from './reputation';
export { summarize } from './summary';
