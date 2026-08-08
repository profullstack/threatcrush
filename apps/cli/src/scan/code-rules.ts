/**
 * Code-level vulnerability rules for `threatcrush scan`.
 *
 * Why this file exists
 * --------------------
 * Measured against the public testbed at `profullstack/malware-test-prs`, the
 * CLI scored 15.6% true-positive rate with a 0.0% false-positive rate: it found
 * every hardcoded credential and none of the code-level classes — no SQL
 * injection, XSS, SSRF, command injection, deserialisation or template
 * injection. ThreatCrush was a secrets scanner wearing a code scanner's name.
 *
 * These rules close that gap without giving up the number that was actually
 * worth having. The false-positive denominator in that testbed is a control
 * group of `SAFE:` lines — each one a *correct* implementation of the same
 * pattern the neighbouring vulnerable code gets wrong. A scanner that flags one
 * is pattern-matching on syntax instead of following the data. So every rule
 * here is built against both halves: it must fire on the vulnerable shape and
 * stay silent on the corrected shape standing next to it.
 *
 * Three mechanisms do that work:
 *
 *   1. **Shape, not keyword.** `db.query("SELECT … $1", [id])` and
 *      `db.query("SELECT … '" + id + "'")` both contain `SELECT`. Only the
 *      second concatenates, and only the second matches.
 *   2. **Guard windows.** A construct is exonerated by the code around it —
 *      an allow-list two lines up, a `realpath` on the same line, an
 *      `ObjectInputFilter` installed before the `readObject()`. Comment lines
 *      are excluded from the window, because a comment saying "no allow-list
 *      here" is not an allow-list.
 *   3. **Confidence.** A construct that merely exists is capped at medium.
 *      Escalation requires visible untrusted input. See `types.ts`.
 *
 * What this is not: data-flow analysis. It is line-oriented matching with a
 * small amount of local context, and it says so. Classes that genuinely need
 * whole-function reasoning — missing CSRF tokens, check-then-use races,
 * integer overflow — are deliberately absent rather than approximated by a
 * rule that would flag every session read in the codebase. See KNOWN_GAPS.
 */

import type { Confidence, ScanLanguage, Severity } from './types.js';
import { severityFor } from './types.js';

export interface CodeRule {
  id: string;
  title: string;
  /** What happens if it is real. An operator triages on consequence. */
  consequence: string;
  cwe: string;
  severity: Severity;
  /** Languages the rule applies to. `undefined` means every language. */
  languages?: readonly ScanLanguage[];
  pattern: RegExp;
  /**
   * The rule describes a construct that is ordinary on its own — reading a
   * file from a computed path is just software. Only report it when untrusted
   * input is visible nearby.
   */
  needsContext?: boolean;
  /**
   * Extra evidence that must appear in the guard window for the rule to fire.
   * Used where the dangerous part is the *combination* — a base64 blob is
   * harmless until something executes it.
   */
  requires?: RegExp;
  /**
   * Evidence that the construct is already handled. `false` opts the rule out
   * of the generic guard entirely — the CWE-532 rules are *about* reading
   * `process.env`, so the generic guard would veto every true positive.
   */
  guard?: RegExp | false;
  /**
   * Evidence — on the matched line ONLY — that this occurrence is safe.
   *
   * Distinct from `guard`, which also searches the surrounding window. That
   * breadth is right for "the value was sanitised three lines up" but wrong
   * for properties of the line itself: a static `innerHTML` assignment says
   * nothing about a dynamic one two lines below it, and a context-scoped
   * guard would silently veto the dynamic one too.
   */
  lineGuard?: RegExp;
  /** Lines of context searched backwards for guards and required evidence. */
  guardBack?: number;
  /**
   * Lines searched *forwards*. Zero for almost everything: code that fixes a
   * problem generally runs before the problem. XML parser hardening is the
   * exception — the factory is constructed, then configured, so the evidence
   * is below the match.
   */
  guardForward?: number;
}

/**
 * Things that look like attacker-controlled input, per language family.
 *
 * Deliberately shallow. It is a heuristic for *ranking*, not a taint-source
 * model. A real source list would be framework-aware and interprocedural,
 * which is exactly what this subsystem promises not to pretend to be.
 */
/**
 * `searchParams` is a read *and* a write API. `params.get('q')` is inbound
 * data; `url.searchParams.set('limit', 50)` is an outbound URL being built,
 * and treating the two alike marked every client of every third-party API as
 * taking untrusted input — which is what made the SSRF rule fire on requests
 * whose host is a compile-time constant. Only the reading half is evidence.
 */
const UNTRUSTED_JS =
  /\b(?:req|request|ctx|context)\s*\.\s*(?:body|query|params|param|headers|cookies|url|files)\b|\bprocess\.argv\b|\bwindow\.location\b|\bdocument\.location\b|\blocation\.(?:search|hash|href)\b|\bsearchParams\s*\.\s*(?:get|getAll|has|entries|keys|values|forEach)\b|\bgetParameter\s*\(|\bgetQueryString\s*\(|\bgetInputStream\s*\(/;

const UNTRUSTED_PY = /\brequest\b|\bparams\b|\bflask\b|\bsys\.argv\b|\bos\.environ\b\s*\[/;

const UNTRUSTED_RB = /\bparams\s*\[|\brequest\b|\bcookies\s*\[/;

const UNTRUSTED_GO =
  /\br\s*\.\s*(?:URL|Form|Body|Header|PostForm)\b|\bFormValue\s*\(|\bQuery\s*\(\s*\)\s*\.\s*Get\s*\(|\bmux\.Vars\s*\(/;

const UNTRUSTED_JAVA =
  /\bgetParameter\s*\(|\bgetQueryString\s*\(|\bgetHeader\s*\(|\bgetInputStream\s*\(|\bgetCookies\s*\(|\b@RequestParam\b|\b@PathVariable\b/;

export function untrustedPatternFor(language: ScanLanguage): RegExp {
  switch (language) {
    case 'python':
      return UNTRUSTED_PY;
    case 'ruby':
      return UNTRUSTED_RB;
    case 'go':
      return UNTRUSTED_GO;
    case 'java':
      return UNTRUSTED_JAVA;
    default:
      return UNTRUSTED_JS;
  }
}

/**
 * Evidence that the dangerous construct on this line is already handled.
 *
 * Every entry here was added because a *correct* implementation in the testbed
 * corpus was otherwise flagged. They are named after what the safe code does,
 * not after what the finding is:
 *
 *   allow/whitelist   an allow-list decides what reaches the sink
 *   escape/sanitize   the value is encoded for its output context
 *   realpath/…        the path is resolved and re-checked before use
 *   process.env/…     the value comes from the environment, not the request
 *   ObjectInputFilter a class allow-list is installed on the stream
 *
 * A guard match suppresses the finding rather than downgrading it. Reporting
 * "we saw an allow-list but flagged it anyway" is the behaviour that makes
 * operators stop reading scanner output.
 */
export const GENERIC_GUARD =
  // `esc(`, `aEsc(`, `htmlEscape(`, `escapeHtml(` — the escaper is almost
  // never *named* `escapeHtml` in real code. It gets aliased to something
  // short because it is called on nearly every interpolation, so matching only
  // the long spellings reported the codebases that escape most rigorously.
  //
  // The identifier must END at the escaper (with at most a known output-context
  // suffix). An earlier, looser form also matched `describe(`, which would have
  // silenced findings across every test file in every repository.
  /\ballow(?:ed|list|_list|ed_hosts)?\b|\bwhitelist\b|\b\w{0,6}[Ee]sc(?:ape)?(?:[Hh]tml|HTML|[Xx]ml|XML|[Ss]ql|[Aa]ttr|[Jj]s|[Uu]ri|[Uu]rl)?\s*\(|\bhtml_escape\b|\bhtmlspecialchars\s*\(|\bsanitiz\w*\b|\bencoded\b|\brealpath\b|\bcommonpath\b|\bresolve\(\)\.startsWith\b|\bprocess\.env\b|\bos\.environ\b|\bgetenv\b|\bENV\s*\[|setObjectInputFilter|ObjectInputFilter/i;

/** Evidence that an XML parser factory has been hardened against XXE. */
const XXE_GUARD =
  /FEATURE_SECURE_PROCESSING|setExpandEntityReferences|disallow-doctype-decl|external-general-entities|external-parameter-entities|setXIncludeAware\s*\(\s*false/;

/** A sink that executes whatever string reaches it. */
const CODE_SINK =
  /\bglobalThis\s*\[|\bconstructor\b|\beval\b|\bFunction\b|\brun\s*\(|\bvm\s*\.\s*run/;

/** A sink whose output is retained: a log, a console, an outbound request. */
const EXFIL_SINK = /\bconsole\s*\.\s*(?:log|debug|info|warn|error)\s*\(|\bfetch\s*\(|\baxios\b|\brequest\s*\(|\.\s*send\s*\(/;

/**
 * SQL text that is being *assembled* rather than parameterised.
 *
 * The four tails are the four ways to build a string in the languages this
 * covers: `+` concatenation, `${}` template interpolation, `%`/`.format()`
 * substitution, and Ruby's `#{}`. A bound placeholder (`$1`, `?`, `%s` passed
 * as an argument) leaves a comma after the closing quote and matches none of
 * them — which is exactly how the safe counterparts stay unflagged.
 */
const SQL_KEYWORDS = 'SELECT|INSERT\\s+INTO|INSERT|UPDATE|DELETE\\s+FROM|DELETE|DROP|UNION\\s+SELECT';

/**
 * A quoted string containing a SQL verb.
 *
 * Two variants, one per quote character, because the interesting strings
 * contain the *other* quote:
 *
 *     "SELECT id FROM users WHERE id = '" + id + "'"
 *
 * A single `["'][^"'\n]*` class stops dead at that inner `'` and matches
 * nothing — which silently drops the most common SQL-injection shape in every
 * language at once. Match a double-quoted string with a class that excludes
 * only `"`, and vice versa.
 */
const SQL_IN_DOUBLE = `"[^"\\n]*(?:${SQL_KEYWORDS})\\b[^"\\n]*"`;
const SQL_IN_SINGLE = `'[^'\\n]*(?:${SQL_KEYWORDS})\\b[^'\\n]*'`;
const SQL_STRING = `(?:${SQL_IN_DOUBLE}|${SQL_IN_SINGLE})`;

export const CODE_RULES: readonly CodeRule[] = [
  // ── Injection: SQL ───────────────────────────────────────────────────────
  {
    id: 'sql-string-concatenation',
    title: 'SQL assembled by concatenation or interpolation',
    consequence:
      'A quote in the interpolated value changes the query’s meaning — the query runs as the attacker wrote it, not as you wrote it.',
    cwe: 'CWE-89',
    severity: 'critical',
    // The tail is what distinguishes assembly from parameterisation. A bound
    // query leaves a comma after the closing quote (`"… = $1", [id]`) and
    // matches none of these.
    pattern: new RegExp(
      `${SQL_STRING}\\s*\\+|` +
        `${SQL_STRING}\\s*%\\s*[\\w(]|` +
        `${SQL_STRING}\\s*\\.\\s*format\\s*\\(|` +
        '\\+\\s*(?:"[^"\\n]*|\'[^\'\\n]*)(?:WHERE|ORDER\\s+BY|VALUES|SET)\\b',
      'i',
    ),
  },
  {
    id: 'sql-template-interpolation',
    title: 'SQL built from a template literal or f-string',
    consequence:
      'Template interpolation is string concatenation with nicer syntax — it binds nothing and escapes nothing.',
    cwe: 'CWE-89',
    severity: 'critical',
    pattern: new RegExp(
      `\`[^\`\\n]*(?:${SQL_KEYWORDS})\\b[^\`\\n]*\\$\\{|` +
        `\\bf"[^"\\n]*(?:${SQL_KEYWORDS})\\b[^"\\n]*\\{|` +
        `\\bf'[^'\\n]*(?:${SQL_KEYWORDS})\\b[^'\\n]*\\{`,
      'i',
    ),
  },
  {
    id: 'sql-format-call',
    title: 'SQL text produced by a format helper',
    consequence:
      '`Sprintf`/`String.format` substitute without quoting; the resulting string is concatenated SQL by another name.',
    cwe: 'CWE-89',
    severity: 'critical',
    languages: ['go', 'java'],
    pattern: new RegExp(
      `\\b(?:fmt\\.Sprintf|String\\.format)\\s*\\(\\s*"[^"\\n]*(?:${SQL_KEYWORDS})\\b`,
      'i',
    ),
  },
  {
    id: 'rb-sql-interpolation',
    title: 'ActiveRecord query built by string interpolation',
    consequence:
      '`where("… #{value}")` interpolates before the adapter sees it, so no binding ever happens.',
    cwe: 'CWE-89',
    severity: 'critical',
    languages: ['ruby'],
    pattern:
      /\b(?:where|find_by_sql|execute|select_all|select_values|order|group|pluck)\s*[( ]\s*(?:"[^"\n]*|'[^'\n]*)#\{/,
  },

  // ── Injection: OS command ────────────────────────────────────────────────
  {
    id: 'js-shell-exec-interpolation',
    title: 'shell execution with an interpolated string',
    consequence: 'A `;` or `$(…)` in the interpolated value runs as the server user.',
    cwe: 'CWE-78',
    severity: 'critical',
    languages: ['javascript', 'typescript'],
    pattern:
      /\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|[a-zA-Z_$][\w$]*\s*\+)/,
  },
  {
    id: 'py-shell-command-string',
    title: 'shell command built from a string',
    consequence:
      '`os.system` and `shell=True` hand the string to `/bin/sh`, which happily interprets metacharacters.',
    cwe: 'CWE-78',
    severity: 'critical',
    languages: ['python'],
    pattern:
      /\bos\.(?:system|popen)\s*\(\s*(?:f?['"][^'"]*['"]\s*(?:\+|%|\.\s*format)|f['"]|[a-zA-Z_]\w*\s*[,)])|\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)]*\bshell\s*=\s*True/,
  },
  {
    id: 'go-shell-exec-command',
    title: 'exec.Command invoking a shell',
    consequence:
      'Passing `sh -c` re-introduces the shell that `exec.Command`’s argv interface exists to avoid.',
    cwe: 'CWE-78',
    severity: 'critical',
    languages: ['go'],
    pattern: /\bexec\.Command(?:Context)?\s*\(\s*(?:ctx\s*,\s*)?"(?:\/bin\/)?(?:sh|bash|zsh|cmd|powershell)"\s*,\s*"(?:-c|\/c)"/,
  },
  {
    id: 'rb-backtick-interpolation',
    title: 'backtick command with interpolation',
    consequence: 'Ruby backticks are a shell invocation; `#{}` inside one is command injection.',
    cwe: 'CWE-78',
    severity: 'critical',
    languages: ['ruby'],
    pattern: /`[^`\n]*#\{|\bsystem\s*\(\s*["'][^"'\n]*#\{|%x\[[^\]]*#\{/,
  },

  // ── Injection: dynamic code ──────────────────────────────────────────────
  {
    id: 'js-dynamic-code-execution',
    title: 'dynamic code execution',
    consequence: 'Any string reaching this call executes as code with the process’ privileges.',
    cwe: 'CWE-95',
    severity: 'critical',
    languages: ['javascript', 'typescript'],
    pattern:
      /\beval\s*\(|\bnew\s+Function\s*\(|\bvm\s*\.\s*run(?:InThisContext|InNewContext|InContext)\s*\(|\bset(?:Timeout|Interval)\s*\(\s*(?:['"`]|(?:req|request|ctx|params|query|body)\b)/,
  },
  {
    id: 'js-indirect-code-sink',
    title: 'code sink reached indirectly',
    consequence:
      'Resolving `eval`/`Function` through `globalThis[…]` or `.constructor` hides the sink from literal matching. Legitimate code has no reason to.',
    cwe: 'CWE-506',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern:
      /\bglobalThis\s*\[\s*[a-zA-Z_$][\w$]*\s*\]|\(\s*function\s*\(\s*\)\s*\{\s*\}\s*\)\s*\.\s*constructor/,
  },
  {
    id: 'js-encoded-payload-execution',
    title: 'encoded blob decoded next to a code sink',
    consequence:
      'A base64 literal that is decoded and executed is the standard shape of a planted backdoor; the encoding exists to defeat review.',
    cwe: 'CWE-506',
    severity: 'critical',
    languages: ['javascript', 'typescript'],
    pattern: /\bBuffer\.from\s*\(\s*[\w.$]+\s*,\s*['"]base64['"]\s*\)|\batob\s*\(\s*[\w.$]+\s*\)/,
    requires: CODE_SINK,
    guardBack: 6,
    guardForward: 3,
  },
  {
    id: 'py-dynamic-code-execution',
    title: 'dynamic code execution',
    consequence: 'Any string reaching this call executes as Python with the process’ privileges.',
    cwe: 'CWE-95',
    severity: 'critical',
    languages: ['python'],
    pattern: /\b(?:eval|exec)\s*\(\s*(?!['"]\s*\))[a-zA-Z_(f'"]/,
    needsContext: true,
  },
  {
    id: 'rb-dynamic-dispatch',
    title: 'dynamic code execution or unrestricted #send',
    consequence:
      '`eval` runs arbitrary Ruby; unrestricted `#send` lets the caller invoke any method on the receiver, including private ones.',
    cwe: 'CWE-95',
    severity: 'critical',
    languages: ['ruby'],
    pattern: /\beval\s*\(|\binstance_eval\s*\(|\bclass_eval\s*\(|\.\s*send\s*\(\s*(?:params|request|args)\b/,
  },

  // ── Cross-site scripting ─────────────────────────────────────────────────
  {
    id: 'js-unescaped-html-sink',
    title: 'unescaped HTML rendering',
    consequence: 'A script tag in the value executes in the victim’s session — stored or reflected XSS.',
    cwe: 'CWE-79',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern:
      /\bdangerouslySetInnerHTML\s*=|\.\s*(?:innerHTML|outerHTML)\s*=\s*(?!\s*['"`]\s*['"`]\s*;?\s*$)|\bdocument\s*\.\s*write(?:ln)?\s*\(|\.\s*insertAdjacentHTML\s*\(/,
    /**
     * A whole-statement assignment of a string with no interpolation and no
     * concatenation carries no data, so it cannot carry attacker data. This
     * was the single largest source of noise: a codebase that builds its UI
     * with innerHTML reports every static heading and spinner as XSS, and a
     * rule that flags 40 safe lines to catch one real one gets switched off.
     *
     * Line-scoped on purpose — see `lineGuard`.
     */
    lineGuard:
      /(?:innerHTML|outerHTML)\s*=\s*(?:'[^'\\]*'|"[^"\\]*"|`[^`$\\]*`)\s*;?\s*$/,
  },
  {
    id: 'java-html-writer-concatenation',
    title: 'HTML written to the response by concatenation',
    consequence:
      'The servlet writer performs no encoding; a value concatenated into markup is rendered as markup.',
    cwe: 'CWE-79',
    severity: 'high',
    languages: ['java'],
    pattern: /\b(?:println|print|write)\s*\(\s*"[^"\n]*<[^"\n]*"\s*\+/,
  },
  {
    id: 'rb-unescaped-output',
    title: 'Rails output escaping bypassed',
    consequence:
      '`html_safe` and `raw` tell Rails the string is already safe. If it came from a parameter, it is not.',
    cwe: 'CWE-79',
    severity: 'high',
    languages: ['ruby'],
    pattern: /\.\s*html_safe\b|\braw\s*\(\s*(?:params|request|@)|\blink_to\s+[^,\n]+,\s*params\s*\[/,
  },
  {
    id: 'py-template-autoescape-off',
    title: 'template rendering with escaping disabled',
    consequence:
      'With autoescape off — or a `|safe` filter — every interpolated value is rendered as markup.',
    cwe: 'CWE-79',
    severity: 'high',
    languages: ['python'],
    pattern: /\bEnvironment\s*\([^)]*\bautoescape\s*=\s*False|\|\s*safe\b|\bMarkup\s*\(\s*(?!['"])/,
  },
  {
    id: 'py-template-from-input',
    title: 'template compiled from a non-literal source',
    consequence:
      'Server-side template injection. In Jinja2 the sandbox is escapable, so this escalates from XSS to remote code execution.',
    cwe: 'CWE-1336',
    severity: 'critical',
    languages: ['python'],
    pattern: /\bTemplate\s*\(\s*(?!['"])[a-zA-Z_]/,
    needsContext: true,
  },

  // ── Server-side request forgery ──────────────────────────────────────────
  {
    id: 'js-ssrf-outbound-request',
    title: 'outbound request to a non-constant URL',
    consequence:
      'An attacker who controls the URL reaches the cloud metadata endpoint, localhost, and every service on the private network.',
    cwe: 'CWE-918',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern:
      /\bfetch\s*\(\s*[a-zA-Z_$][\w$]*\s*[,)]|\bhttps?\s*\.\s*(?:get|request)\s*\(\s*[a-zA-Z_$][\w$]*\s*[,)]|\baxios\s*\.\s*get\s*\(\s*[a-zA-Z_$][\w$]*\s*[,)]/,
    needsContext: true,
  },
  {
    id: 'py-ssrf-outbound-request',
    title: 'outbound request to a non-constant URL',
    consequence:
      'An attacker who controls the URL reaches the cloud metadata endpoint, localhost, and every service on the private network.',
    cwe: 'CWE-918',
    severity: 'high',
    languages: ['python'],
    pattern:
      /\brequests\.(?:get|request|head)\s*\(\s*[a-zA-Z_]\w*\s*[,)]|\burlopen\s*\(\s*[a-zA-Z_]\w*\s*[,)]|\bhttpx\.get\s*\(\s*[a-zA-Z_]\w*\s*[,)]/,
    needsContext: true,
  },
  {
    id: 'go-ssrf-outbound-request',
    title: 'outbound request to a non-constant URL',
    consequence:
      'An attacker who controls the URL reaches the cloud metadata endpoint, localhost, and every service on the private network.',
    cwe: 'CWE-918',
    severity: 'high',
    languages: ['go'],
    pattern: /\bhttp\.(?:Get|Post|Head)\s*\(\s*(?:[a-zA-Z_]\w*\s*[,)]|"[^"]*"\s*\+)/,
    needsContext: true,
  },

  // ── Open redirect ────────────────────────────────────────────────────────
  {
    id: 'js-open-redirect',
    title: 'redirect to a non-constant destination',
    consequence:
      'Your domain becomes the credible first hop of a phishing chain; the victim sees your hostname in the link they clicked.',
    cwe: 'CWE-601',
    severity: 'medium',
    languages: ['javascript', 'typescript'],
    pattern:
      /\b(?:res|response)\s*\.\s*redirect\s*\(\s*[a-zA-Z_$][\w$]*\s*\)|\bwindow\s*\.\s*location(?:\s*\.\s*(?:href|replace))?\s*(?:=\s*[a-zA-Z_$]|\(\s*[a-zA-Z_$][\w$]*\s*\))/,
    needsContext: true,
  },

  // ── Deserialisation ──────────────────────────────────────────────────────
  {
    id: 'py-unsafe-deserialization',
    title: 'deserialisation of untrusted data',
    consequence:
      '`pickle` and `yaml.load` instantiate arbitrary types during parsing — a crafted payload is remote code execution, not a parse error.',
    cwe: 'CWE-502',
    severity: 'critical',
    languages: ['python'],
    pattern: /\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(|\bmarshal\.loads\s*\(|\byaml\.load\s*\(|\bjsonpickle\.decode\s*\(/,
  },
  {
    id: 'java-unsafe-deserialization',
    title: 'Java deserialisation without a class filter',
    consequence:
      'A gadget chain in the classpath turns `readObject()` on attacker bytes into remote code execution.',
    cwe: 'CWE-502',
    severity: 'critical',
    languages: ['java'],
    pattern: /\breadObject\s*\(\s*\)|\bnew\s+ObjectInputStream\s*\(/,
    guardBack: 8,
    // The stream is constructed, *then* filtered. Without a forward window the
    // guarded case matches on its constructor line and reports a correct
    // implementation as a finding.
    guardForward: 6,
  },
  {
    id: 'js-unsafe-yaml-load',
    title: 'YAML parsed with type resolution enabled',
    consequence: 'A crafted document can instantiate arbitrary types during parsing.',
    cwe: 'CWE-502',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern: /\byaml\s*\.\s*load\s*\((?![^)]*safe)|\bloadAll\s*\([^)]*unsafe/i,
  },

  // ── XML external entities ────────────────────────────────────────────────
  {
    id: 'java-xxe-parser-defaults',
    title: 'XML parser left on its insecure defaults',
    consequence:
      'External entity expansion reads local files and makes outbound requests on the parser’s behalf — file disclosure and SSRF from a document.',
    cwe: 'CWE-611',
    severity: 'high',
    languages: ['java'],
    pattern:
      /\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\s*\.\s*newInstance\s*\(\s*\)/,
    guard: XXE_GUARD,
    guardBack: 4,
    guardForward: 8,
  },
  {
    id: 'java-xxe-parse-call',
    title: 'XML parsed by a builder that was never hardened',
    consequence:
      'The expansion happens at `parse()`. Flagging only the factory misses the line where the document is actually read.',
    cwe: 'CWE-611',
    severity: 'high',
    languages: ['java'],
    // Receiver-qualified so `LocalDate.parse(s)` and friends stay out of it.
    pattern: /\b\w*(?:[Bb]uilder|[Pp]arser|[Rr]eader)\s*\.\s*parse\s*\(/,
    guard: XXE_GUARD,
    guardBack: 6,
    guardForward: 4,
  },

  // ── Path traversal ───────────────────────────────────────────────────────
  {
    id: 'py-path-traversal',
    title: 'file opened at a path built from input',
    consequence: 'A `../` sequence — or an absolute path — reads or writes outside the intended directory.',
    cwe: 'CWE-22',
    severity: 'high',
    languages: ['python'],
    pattern: /\bopen\s*\(\s*(?:os\.path\.join\s*\(|[a-zA-Z_]\w*\s*\+|f['"])/,
    needsContext: true,
  },
  {
    id: 'js-path-traversal',
    title: 'file path built from a variable',
    consequence: 'A `../` sequence in the value reads or writes outside the intended directory.',
    cwe: 'CWE-22',
    severity: 'medium',
    languages: ['javascript', 'typescript'],
    pattern:
      /\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|sendFile)\s*\(\s*(?:`[^`]*\$\{|[a-zA-Z_$][\w$]*\s*\+|path\.join\s*\([^)]*(?:req|request)\b)/,
    needsContext: true,
  },

  // ── Cryptography, tokens, randomness ─────────────────────────────────────
  {
    id: 'js-jwt-decode-without-verify',
    title: 'JWT decoded without verifying the signature',
    consequence:
      '`decode` parses the claims and checks nothing. Anyone can mint a token with any `sub` and any `role`.',
    cwe: 'CWE-347',
    severity: 'critical',
    languages: ['javascript', 'typescript'],
    pattern: /\bjwt\s*\.\s*decode\s*\(|\bjsonwebtoken\s*\.\s*decode\s*\(|\bdecodeJwt\s*\(/,
  },
  {
    id: 'tls-verification-disabled',
    title: 'TLS certificate verification disabled',
    consequence:
      'Every connection made this way is trivially interceptable; the encryption is decorative.',
    cwe: 'CWE-295',
    severity: 'high',
    pattern:
      /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0|strictSSL\s*:\s*false|\bverify\s*=\s*False\b|InsecureSkipVerify\s*:\s*true/,
  },
  {
    id: 'weak-hash-on-credential',
    title: 'broken hash used on a credential',
    consequence: 'MD5 and SHA-1 are fast and collision-prone; hashed passwords are recoverable.',
    cwe: 'CWE-327',
    severity: 'high',
    pattern:
      /(?:createHash|hashlib|MessageDigest\.getInstance|Digest::)\s*[.(]?\s*['"]?(?:md5|MD5|sha1|SHA-?1)['"]?\s*\)?[\s\S]{0,80}(?:password|passwd|secret|token|credential)/i,
  },
  {
    id: 'insecure-randomness-for-secret',
    title: 'predictable randomness used for a security value',
    consequence:
      '`Math.random`/`random.random` are predictable; tokens, session ids and reset codes built from them are guessable.',
    cwe: 'CWE-338',
    severity: 'high',
    pattern:
      /(?:token|secret|password|salt|nonce|session|otp|reset|apikey|api_key)[\w]*\s*[:=][^;\n]{0,60}(?:Math\s*\.\s*random\s*\(|\brandom\s*\.\s*(?:random|randint|choice)\s*\(|\brand\s*\()/i,
  },
  {
    id: 'redos-nested-quantifier',
    title: 'regex with nested unbounded quantifiers',
    consequence:
      'Catastrophic backtracking: a crafted input of a few dozen characters pins a CPU core for minutes.',
    cwe: 'CWE-1333',
    severity: 'medium',
    pattern: /\([^)\n]*[+*]\s*\)\s*[+*]|\([^)\n]*\{\d+,\}\s*\)\s*[+*{]/,
  },

  // ── Temporary files ──────────────────────────────────────────────────────
  {
    id: 'insecure-temp-file',
    title: 'predictable temporary file path',
    consequence:
      'A predictable name in a world-writable directory is a symlink attack: an attacker pre-creates the path and your process writes through it.',
    cwe: 'CWE-377',
    severity: 'medium',
    // A hardcoded path under /tmp is the finding whether or not it is
    // formatted: `"/tmp/application.log.tmp"` is worse than the PID-based one,
    // because every process on the host can predict it exactly.
    pattern:
      /\btempfile\.mktemp\s*\(|\bos\.tmpnam\s*\(|['"]\/tmp\/[^'"\n]+['"]|['"]\/tmp\/[^'"\n]*\{|\bFile\.createTempFile\s*\(/,
  },

  // ── Information exposure ─────────────────────────────────────────────────
  {
    id: 'py-stack-trace-returned',
    title: 'stack trace returned to the caller',
    consequence:
      'Tracebacks leak absolute paths, dependency versions and source fragments — the reconnaissance an attacker would otherwise have to guess at.',
    cwe: 'CWE-209',
    severity: 'medium',
    languages: ['python'],
    pattern: /\breturn\b[^\n]*\btraceback\.(?:format_exc|format_exception|print_exc)\s*\(|\breturn\b[^\n]*\bstr\s*\(\s*e\s*\)/,
  },
  {
    id: 'js-environment-exfiltration',
    title: 'process environment serialised into a payload',
    consequence:
      'The environment is where every secret lives. Serialising it whole into a request body is credential exfiltration regardless of the endpoint.',
    cwe: 'CWE-532',
    severity: 'critical',
    languages: ['javascript', 'typescript'],
    pattern: /\bJSON\.stringify\s*\(\s*\{?[^)]*\bprocess\.env\b(?!\s*\.)/,
    guard: false,
  },
  {
    id: 'js-credential-logged',
    title: 'credential read from the environment into a log sink',
    consequence:
      'CI retains job logs, and on public forks it publishes them. A token printed once is a token leaked permanently.',
    cwe: 'CWE-532',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern: /\b(?:token|apiKey|api_key|secret|password|credential|auth)\w*\s*:\s*process\.env\.\w+/i,
    requires: EXFIL_SINK,
    guard: false,
    guardBack: 4,
    guardForward: 1,
  },

  // ── Prototype pollution ──────────────────────────────────────────────────
  {
    id: 'js-prototype-pollution',
    title: 'write to a prototype-reachable key',
    consequence:
      'An attacker-supplied `__proto__` key changes behaviour for every object in the process, including ones it never touched.',
    cwe: 'CWE-1321',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern:
      /\[\s*['"]__proto__['"]\s*\]|\bObject\s*\.\s*assign\s*\(\s*[\w.$]*\.prototype\b|\.\s*__proto__\s*=/,
  },
];

/**
 * Classes deliberately not implemented, and why.
 *
 * Recorded in code rather than in a document because the reason is a design
 * constraint, not a backlog item: each of these needs reasoning this scanner
 * does not do, and the line-oriented approximation of each one flags ordinary
 * software. A missing detection is a known number. A rule that fires on every
 * session read is a scanner nobody runs twice.
 */
export const KNOWN_GAPS: readonly { cwe: string; name: string; why: string }[] = [
  {
    cwe: 'CWE-352',
    name: 'Missing CSRF token',
    why: 'Requires knowing that a handler is state-changing and that no token check dominates the mutation. Line-locally, the vulnerable and the guarded handler are the same code.',
  },
  {
    cwe: 'CWE-362',
    name: 'Check-then-use race (TOCTOU)',
    why: 'Requires pairing a check with a later use of the same path across statements. A rule matching either half alone flags every `os.path.exists`.',
  },
  {
    cwe: 'CWE-190',
    name: 'Integer overflow / unchecked narrowing',
    why: 'Requires range reasoning about the operands. Flagging arithmetic on a request value would flag arithmetic.',
  },
  {
    cwe: 'CWE-1321',
    name: 'Prototype pollution via generic dynamic assignment',
    why: '`target[key] = source[key]` is both the vulnerable merge and the guarded one; only a denylist several lines away distinguishes them. The explicit `__proto__` shapes are covered.',
  },
];

export interface MatchContext {
  /** All lines of the file, 0-indexed. */
  lines: readonly string[];
  /** 0-indexed position of the line being tested. */
  index: number;
  language: ScanLanguage;
  /**
   * Indexes inside a multi-line string or block comment, from `proseLines`.
   * Treated exactly like comment lines: not scanned, not guard evidence.
   */
  prose?: ReadonlySet<number>;
}

const COMMENT_PREFIX = /^\s*(?:\/\/|\/\*|\*|#|--|<!--)/;

/**
 * A line that introduces a name rather than doing something with it.
 *
 * Excluded from guard windows because a *name* is not evidence. The corpus
 * contains `def sanitize_path_vulnerable(path):` directly above three
 * catastrophic-backtracking regexes: reading that signature as proof of
 * sanitisation suppressed all three. Naming a function `sanitize` does not
 * sanitise anything, and neither does calling one `validate` or `escape`.
 */
const DEFINITION_PREFIX =
  /^\s*(?:(?:export|public|private|protected|static|final|async|abstract)\s+)*(?:def|function|func|class|module|interface|struct|impl|fn|sub)\b/;

/**
 * Comment lines are documentation, not code.
 *
 * Excluded from guard windows for a reason found the hard way: the testbed's
 * vulnerable cases carry comments like "No `__proto__` guard" and "without
 * allow-list validation". Reading those as evidence of a guard suppresses
 * exactly the findings the corpus exists to measure.
 */
export function isComment(line: string): boolean {
  return COMMENT_PREFIX.test(line);
}

/**
 * Line indexes belonging to multi-line strings and block comments.
 *
 * Python module docstrings are the case that forced this. Every file in the
 * testbed opens with a `"""…"""` header describing the vulnerability it
 * contains — `pickle.loads`, `(a+)+`, `autoescape=False` — and scanning that
 * prose produces findings *about the documentation*, reported at line 9 of a
 * file whose code starts at line 18. They are unattributable by construction,
 * and they are the scanner reading its own description back to itself.
 */
export function proseLines(lines: readonly string[]): Set<number> {
  const inside = new Set<number>();
  let delimiter: string | null = null;

  lines.forEach((line, index) => {
    if (delimiter) {
      inside.add(index);
      if (line.includes(delimiter)) delimiter = null;
      return;
    }
    for (const candidate of ['"""', "'''"]) {
      const start = line.indexOf(candidate);
      if (start === -1) continue;
      // A docstring opened and closed on one line encloses nothing.
      if (line.indexOf(candidate, start + candidate.length) !== -1) return;
      delimiter = candidate;
      inside.add(index);
      return;
    }
  });

  return inside;
}

function skippable(line: string, index: number, prose?: ReadonlySet<number>): boolean {
  return isComment(line) || DEFINITION_PREFIX.test(line) || (prose?.has(index) ?? false);
}

function windowText(
  lines: readonly string[],
  index: number,
  back: number,
  forward: number,
  prose?: ReadonlySet<number>,
): string {
  const from = Math.max(0, index - back);
  const to = Math.min(lines.length - 1, index + forward);
  const collected: string[] = [];
  for (let i = from; i <= to; i += 1) {
    const line = lines[i] ?? '';
    if (i !== index && skippable(line, i, prose)) continue;
    collected.push(line);
  }
  return collected.join('\n');
}

export interface RuleMatch {
  rule: CodeRule;
  confidence: Confidence;
  severity: Severity;
}

/**
 * Test one rule against one line.
 *
 * Returns `null` when the rule does not apply, does not match, is guarded, or
 * needs context it cannot see.
 */
export function evaluateRule(rule: CodeRule, ctx: MatchContext): RuleMatch | null {
  if (rule.languages && !rule.languages.includes(ctx.language)) return null;

  const line = ctx.lines[ctx.index] ?? '';
  if (isComment(line) || ctx.prose?.has(ctx.index)) return null;
  if (!rule.pattern.test(line)) return null;

  const back = rule.guardBack ?? 8;
  const forward = rule.guardForward ?? 0;
  const context = windowText(ctx.lines, ctx.index, back, forward, ctx.prose);

  if (rule.requires && !rule.requires.test(context)) return null;

  if (rule.lineGuard?.test(line)) return null;

  const guard = rule.guard === undefined ? GENERIC_GUARD : rule.guard;
  if (guard && (guard.test(line) || guard.test(context))) return null;

  const untrusted = untrustedPatternFor(ctx.language);
  const contextual = untrusted.test(line) || untrusted.test(context);
  if (rule.needsContext && !contextual) return null;

  const confidence: Confidence = contextual ? 'contextual' : 'pattern';
  return { rule, confidence, severity: severityFor(rule.severity, confidence) };
}
