/**
 * Shared vocabulary for `threatcrush scan`.
 *
 * The scan pipeline is deliberately three separable pieces — rules produce
 * findings, the engine walks the tree, the reporters serialise. Keeping the
 * types here means a reporter never has to import a rule table to know what a
 * finding looks like.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * How much the scanner is claiming.
 *
 * `pattern`     the dangerous construct is present on the line. Nothing more.
 * `contextual`  the construct sits alongside something that looks like
 *               attacker-controlled input. Still not proof of exploitability,
 *               but a materially stronger claim — and the only one allowed to
 *               present at the rule's full severity.
 * `evidence`    the match *is* the finding, not a proxy for it. A hardcoded
 *               AWS key is a committed credential whether or not any request
 *               ever reaches it, so the severity cap below does not apply.
 *
 * This mirrors the confidence model in `modules/code-scanner` (PRD 0004), for
 * the same reason: a regex is not data-flow analysis, and a scanner that blurs
 * the two produces confident-sounding findings that waste triage time.
 */
export type Confidence = 'pattern' | 'contextual' | 'evidence';

export type ScanLanguage =
  | 'javascript'
  | 'typescript'
  | 'python'
  | 'ruby'
  | 'go'
  | 'java'
  | 'php'
  | 'shell'
  | 'config'
  | 'other';

export interface ScanFinding {
  /** Stable rule identifier, e.g. `js-sql-string-building`. Used as the SARIF ruleId. */
  ruleId: string;
  /** Short human title for the construct, e.g. "SQL assembled by concatenation". */
  title: string;
  /** Path relative to the scan root, POSIX-separated. */
  file: string;
  /** 1-based. Whole-file findings report 1, never 0 — SARIF forbids 0. */
  line: number;
  severity: Severity;
  confidence: Confidence;
  /** What was found, in a sentence. Shown to the operator. */
  message: string;
  /** What happens if it is real. An operator triages on consequence. */
  consequence?: string;
  /** `CWE-89`. Absent for findings with no clean CWE mapping. */
  cwe?: string;
  /**
   * The matched source line, trimmed. Redacted by the reporters for secret
   * findings — see `redactSecret`.
   */
  excerpt: string;
  /** True when `excerpt` may contain credential material. */
  sensitive?: boolean;
  category: 'secret' | 'code' | 'manifest' | 'dependency' | 'file';
}

export const SEVERITY_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function severityRank(severity: Severity): number {
  const index = SEVERITY_ORDER.indexOf(severity);
  return index === -1 ? 0 : index;
}

/**
 * Cap for a bare pattern match.
 *
 * A construct that merely *exists* never presents as high or critical. Enforced
 * centrally rather than per-rule so no future rule can opt out of it by
 * accident.
 */
export function severityFor(declared: Severity, confidence: Confidence): Severity {
  if (confidence !== 'pattern') return declared;
  return severityRank(declared) > severityRank('medium') ? 'medium' : declared;
}
