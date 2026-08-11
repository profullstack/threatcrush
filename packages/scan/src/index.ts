/**
 * `@threatcrush/scan` — the rules and the text engine.
 *
 * This entry point is deliberately free of `node:` imports. Everything here
 * runs in a browser, a service worker or a Node process alike, because the
 * whole of it operates on strings that somebody else obtained. That is what
 * lets the web app, the extension and the desktop renderer share one copy of
 * the rules with the CLI rather than growing their own.
 *
 * Anything needing a filesystem — walking a tree, reading a manifest off disk,
 * writing SARIF — lives behind `@threatcrush/scan/node`.
 */

export { CODE_RULES, evaluateRule, GENERIC_GUARD, proseLines, untrustedPatternFor } from './code-rules.js';
export type { CodeRule } from './code-rules.js';

export { scanPackageJson, scanRequirementsTxt, detectTyposquat, editDistance } from './manifest-rules.js';
export type { ManifestFinding, SquatVerdict } from './manifest-rules.js';

export { isKnownPlaceholder, redactSecret, SECRET_RULES, SENSITIVE_FILES } from './secret-rules.js';

export {
  collectSuppressions,
  isTestPath,
  languageOf,
  languageOfShebang,
  meetsFailThreshold,
  peakSeverity,
  SCAN_EXTENSIONS,
  scanManifest,
  scanText,
  SKIP_DIRS,
} from './text.js';
export type { Suppressions } from './text.js';

export { severityRank, SEVERITY_ORDER } from './types.js';
export type { Confidence, ScanFinding, ScanLanguage, Severity } from './types.js';
