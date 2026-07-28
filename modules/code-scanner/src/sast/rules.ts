/**
 * Source-pattern rules — the `sast` subsystem of `code-scanner`.
 *
 * Implements PRD 0004. The governing constraint is stated there and repeated
 * here because it is the whole design: **a regex is not data-flow analysis**,
 * and a tool that blurs the two is worse than no tool. It produces
 * confident-sounding findings that waste triage time and, once disproven,
 * discredit the accurate findings standing next to them.
 *
 * So confidence is part of the finding, not part of the prose:
 *
 *   `pattern`     the dangerous construct exists. Capped at medium severity,
 *                 structurally — there is no code path by which a bare pattern
 *                 match becomes a high.
 *   `contextual`  the construct appears alongside something that looks like
 *                 untrusted input. Still not proof, but a different claim, and
 *                 the only kind allowed to escalate.
 *
 * CodeQL and Semgrep already run in this repo's CI and do the real analysis.
 * This exists for what they cannot see: source on a running server that never
 * passed through the repository.
 */

export type SastSeverity = 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'pattern' | 'contextual';

export interface SastRule {
  id: string;
  /** What the construct is. */
  title: string;
  /** What happens if it is real. An operator triages on consequence. */
  consequence: string;
  cwe: string;
  pattern: RegExp;
  /** Severity when the rule fires with `contextual` confidence. */
  severity: SastSeverity;
  /**
   * When set, the rule only escalates to `contextual` if this also appears on
   * the line. Absent means the construct is dangerous regardless of input.
   */
  needsContext?: boolean;
}

/**
 * Things that look like attacker-controlled input.
 *
 * Deliberately shallow — it is a heuristic for *ranking*, not a taint source
 * model. A real source list would be framework-aware and interprocedural,
 * which is exactly what this subsystem promises not to pretend to be.
 */
export const UNTRUSTED = /\b(?:req|request|ctx|context)\s*\.\s*(?:body|query|params|headers|cookies|url)\b|\bprocess\.argv\b|\bwindow\.location\b|\bdocument\.location\b|\blocation\.(?:search|hash|href)\b|\bsearchParams\b/;

export const SAST_RULES: readonly SastRule[] = [
  {
    id: 'js-eval-call',
    title: 'dynamic code execution',
    consequence: 'Any string reaching this call executes as code with the process’ privileges.',
    cwe: 'CWE-95',
    pattern: /\beval\s*\(|\bnew\s+Function\s*\(|\bvm\s*\.\s*runInThisContext\s*\(/,
    severity: 'critical',
  },
  {
    id: 'js-exec-interpolation',
    title: 'shell execution with an interpolated string',
    consequence: 'A shell metacharacter in the interpolated value runs as the server user.',
    cwe: 'CWE-78',
    // Only interpolated forms. `exec('ls')` with a literal is not a finding.
    pattern: /\b(?:exec|execSync|spawnSync?)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/,
    severity: 'critical',
  },
  {
    id: 'js-sql-concatenation',
    title: 'SQL assembled by concatenation or interpolation',
    consequence: 'Input containing a quote can change the query’s meaning — classic SQL injection.',
    cwe: 'CWE-89',
    pattern:
      /\b(?:query|execute|raw)\s*\(\s*(?:`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^`]*\$\{|['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^'"]*['"]\s*\+)/i,
    severity: 'critical',
  },
  {
    id: 'js-unsafe-html',
    title: 'unescaped HTML rendering',
    consequence: 'A script tag in the value executes in the victim’s session — stored or reflected XSS.',
    cwe: 'CWE-79',
    pattern:
      /\bdangerouslySetInnerHTML\s*=|\.innerHTML\s*=\s*(?!['"`]\s*['"`])|\bdocument\s*\.\s*write\s*\(/,
    severity: 'high',
  },
  {
    id: 'js-tls-verification-disabled',
    title: 'TLS certificate verification disabled',
    consequence:
      'Every connection made this way is trivially interceptable; the encryption is decorative.',
    cwe: 'CWE-295',
    pattern:
      /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0|strictSSL\s*:\s*false/,
    severity: 'high',
  },
  {
    id: 'js-weak-hash-for-secret',
    title: 'broken hash used on a credential',
    consequence: 'MD5 and SHA-1 are fast and collision-prone; hashed passwords are recoverable.',
    cwe: 'CWE-327',
    pattern: /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)[\s\S]{0,80}(?:password|passwd|secret|token)/i,
    severity: 'high',
  },
  {
    id: 'js-insecure-randomness',
    title: 'Math.random() used for a security value',
    consequence:
      'Math.random is predictable; tokens, session ids and reset codes built from it are guessable.',
    cwe: 'CWE-338',
    pattern:
      /(?:token|secret|password|salt|nonce|session|otp|reset|apikey|api_key)[\w]*\s*[:=][^;\n]{0,60}Math\s*\.\s*random\s*\(/i,
    severity: 'high',
  },
  {
    id: 'js-path-traversal',
    title: 'filesystem path built from a variable',
    consequence: 'A `../` sequence in the value reads or writes outside the intended directory.',
    cwe: 'CWE-22',
    pattern:
      /\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|sendFile)\s*\(\s*(?:`[^`]*\$\{|[a-zA-Z_$][\w$]*\s*\+)/,
    severity: 'medium',
    needsContext: true,
  },
  {
    id: 'js-unsafe-yaml-load',
    title: 'YAML parsed with type resolution enabled',
    consequence: 'A crafted document can instantiate arbitrary types during parsing.',
    cwe: 'CWE-502',
    pattern: /\byaml\s*\.\s*load\s*\((?![^)]*safe)|loadAll\s*\([^)]*unsafe/i,
    severity: 'high',
  },
  {
    id: 'js-prototype-pollution',
    title: 'merge or assignment onto a prototype',
    consequence:
      'An attacker-supplied `__proto__` key changes behaviour for every object in the process.',
    cwe: 'CWE-1321',
    pattern: /\[\s*['"]__proto__['"]\s*\]|Object\s*\.\s*assign\s*\(\s*[\w.$]*\.prototype\b/,
    severity: 'high',
  },
];

export interface SastFinding {
  ruleId: string;
  title: string;
  consequence: string;
  cwe: string;
  severity: SastSeverity;
  confidence: Confidence;
  line: number;
  /** The source line, trimmed. Safe to show — unlike a secret. */
  excerpt: string;
}

/**
 * Cap for a bare pattern match.
 *
 * PRD 0004's central promise: a construct that merely *exists* never presents
 * as high or critical. Enforced here rather than per-rule so no future rule can
 * opt out of it by accident.
 */
export function severityFor(rule: SastRule, confidence: Confidence): SastSeverity {
  if (confidence === 'contextual') return rule.severity;
  const order: SastSeverity[] = ['low', 'medium', 'high', 'critical'];
  return order[Math.min(order.indexOf(rule.severity), order.indexOf('medium'))]!;
}

const SUPPRESS = /threatcrush-disable-next-line\s+([\w-]+)(?:\s+(.*))?/;

export interface SuppressionRecord {
  line: number;
  ruleId: string;
  reason: string;
}

export interface SastScanResult {
  findings: SastFinding[];
  /** Counted and reported: a quiet scan full of suppressions is not clean. */
  suppressions: SuppressionRecord[];
}

/**
 * Scan a source file's text.
 *
 * Line-oriented on purpose. The moment this wants an AST it has become a
 * different project, and the honest move is to defer to Semgrep rather than
 * grow one badly.
 */
export function scanSource(text: string): SastScanResult {
  const lines = text.split('\n');
  const findings: SastFinding[] = [];
  const suppressions: SuppressionRecord[] = [];

  // A suppression on line N applies to line N+1.
  const suppressed = new Map<number, string>();
  lines.forEach((line, index) => {
    const match = SUPPRESS.exec(line);
    if (match?.[1]) {
      suppressed.set(index + 1, match[1]);
      suppressions.push({
        line: index + 1,
        ruleId: match[1],
        reason: match[2]?.trim() || '(no reason given)',
      });
    }
  });

  lines.forEach((line, index) => {
    // Comment-only lines are documentation, including this module's own rule
    // descriptions. Scanning them produces findings about the scanner.
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) return;

    for (const rule of SAST_RULES) {
      if (!rule.pattern.test(line)) continue;
      if (suppressed.get(index) === rule.id) continue;

      const contextual = UNTRUSTED.test(line);
      // A rule flagged `needsContext` describes a construct that is ordinary
      // on its own — reading a file from a computed path is just software.
      if (rule.needsContext && !contextual) continue;

      const confidence: Confidence = contextual ? 'contextual' : 'pattern';
      findings.push({
        ruleId: rule.id,
        title: rule.title,
        consequence: rule.consequence,
        cwe: rule.cwe,
        severity: severityFor(rule, confidence),
        confidence,
        line: index + 1,
        excerpt: trimmed.slice(0, 200),
      });
    }
  });

  return { findings, suppressions };
}
