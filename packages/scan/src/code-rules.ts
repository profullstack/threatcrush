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

import { NODE_RULES } from './node-rules';
import type { Confidence, ScanLanguage, Severity } from './types';
import { severityFor } from './types';

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
   * The construct *is* the defect, so its severity does not depend on context.
   *
   * The default model caps a finding at medium unless untrusted input is
   * visible nearby, which is right for injection: `exec(cmd)` is only a
   * vulnerability once `cmd` can be influenced. It is wrong for a whole class
   * of rules where nothing nearby changes the answer. `curl -k` against HTTPS
   * is a machine-in-the-middle hole whether or not a positional parameter
   * appears six lines above it; DES is broken in every file that uses it.
   *
   * Marking those rules `inherent` reports them at confidence `evidence` and
   * at their declared severity, the same treatment the credential rules get
   * for the same reason — a committed AWS key is a committed AWS key.
   *
   * Do not reach for this to make a rule look important. It is for rules whose
   * finding text would be identical no matter what surrounds the line.
   */
  inherent?: boolean;
  /**
   * Extra evidence that must appear in the guard window for the rule to fire.
   * Used where the dangerous part is the *combination* — a base64 blob is
   * harmless until something executes it.
   */
  requires?: RegExp;
  /**
   * Evidence that must appear somewhere in the file, not merely in the guard
   * window.
   *
   * For rules whose *applicability* is settled far from the match. Whether a
   * `.parse()` call is XML parsing is decided by an import at the top of the
   * file, which in a 1,600-line source is nowhere near the line that matched;
   * widening `guardBack` far enough to reach it would drag in unrelated
   * evidence for every other rule. Distinct from `requires`, which asks
   * whether the surrounding lines complete a dangerous combination.
   */
  fileRequires?: RegExp;
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
  /**
   * Evidence that the match sits inside a call that cannot be a sink —
   * matched against the callee of each unclosed call enclosing the line.
   *
   * Distinct from `guard` and `lineGuard`, both of which ask what is *near*
   * the match. Neither can answer "is this an argument to something", and that
   * is the question that separates a CORS header from a log line:
   *
   *     console.log('connection', {
   *       headers: { origin: request.headers.origin },
   *     });
   *
   * The reflected-origin rule matched the inner line, four lines below the
   * `console.log(` that makes it inert. A window guard wide enough to see the
   * logger would also exonerate a genuine reflection written four lines under
   * an unrelated log statement; nesting is the only thing that distinguishes
   * them, so nesting is what this reads.
   */
  enclosingCallGuard?: RegExp;
  /**
   * Exonerate a template literal whose every `${…}` names a file-local `const`
   * bound to a string literal.
   *
   *     const SRC = '/srv/app/routes';
   *     execSync(`find ${SRC} -name '*.js'`);
   *
   * The command is a compile-time constant written in two pieces. Nothing
   * reaches it, so nothing can be injected into it — the shape is a build
   * script naming its own directories, and it is most of what the
   * interpolated-exec rules find in practice.
   *
   * `const` only, and a plain string literal only. `let` can be reassigned
   * from a request between the binding and the call, and a binding built by
   * interpolation just moves the question somewhere this cannot follow.
   */
  constantInterpolationGuard?: boolean;
  /**
   * Exonerate an uninitialised buffer that is written into before it escapes.
   *
   *     const out = Buffer.allocUnsafe(length);
   *     src.copy(out, 0, start, start + firstLen);
   *     return out;
   *
   * `allocUnsafe` hands back unzeroed heap and the leak it enables is real, but
   * "I will fill this myself" is the entire reason the API exists. A rule that
   * fires on every call reports correct code as a vulnerability, and both hits
   * on the repository this was found against were a PTY ring that writes every
   * byte it later hands out. Neither could be silenced without silencing the
   * rule everywhere.
   *
   * Bound to the *name* the allocation is assigned to, not to a write merely
   * appearing nearby: an unrelated `.copy(` below an escaping `allocUnsafe`
   * must not exonerate it.
   *
   * The trade is deliberate and worth stating plainly. This cannot prove the
   * write covers the whole buffer, so a partial fill — `src.copy(out, 0, 0, 5)`
   * into a hundred-byte buffer — is exonerated and still leaks the rest.
   * Proving coverage needs range analysis this engine does not do. The
   * alternative is the status quo, where the rule fires on every correct use,
   * is read as noise and gets switched off — which catches that partial write
   * in exactly the same number of cases, namely none.
   *
   * An allocation with no binding to follow is never exonerated:
   * `return Buffer.allocUnsafe(n)` and `send(Buffer.allocUnsafe(n))` hand the
   * unzeroed memory straight out, which is the shape of the actual defect.
   */
  filledBeforeUseGuard?: boolean;
  /**
   * Exonerate an HTML sink when its value was produced by an explicit HTML
   * sanitiser or escaper, including a `const` previously assigned from one.
   * This is opt-in: generic names such as `html` or `content` are never proof
   * that a value is safe.
   */
  sanitizedHtmlGuard?: boolean;
  /** Exonerate a redirect destination derived by a named redirect validator. */
  safeRedirectGuard?: boolean;
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

/**
 * Untrusted input to a shell script: what the caller controls.
 *
 * Positional parameters and `read` are the whole surface. Environment
 * variables are deliberately absent — a script's own configuration arrives
 * that way, so treating `$PREFIX` as attacker-controlled would mark every
 * line of every installer.
 */
const UNTRUSTED_SH =
  /\$\{?[1-9]\d*\b|\$[@*]|\$\{@\}|\bread\s+(?:-\S+\s+)*[A-Za-z_]\w*|\$\{?REPLY\b|\$\{?QUERY_STRING\b/;

/** PHP's superglobals are the request, verbatim. */
const UNTRUSTED_PHP =
  /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\bphp:\/\/input\b|\bgetallheaders\s*\(/;

export function untrustedPatternFor(language: ScanLanguage): RegExp {
  switch (language) {
    case 'php':
      return UNTRUSTED_PHP;
    case 'shell':
      return UNTRUSTED_SH;
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
  // The `Access-Control-` lookbehind is not a nicety. This regex is
  // case-insensitive, and `Access-Control-Allow-Origin` contains the word
  // "Allow" followed by a non-word character — so the CORS header name matched
  // the allow-list heuristic. Because the guard is tested against an 8-line
  // *window*, one header line silently disabled every guardable rule near it:
  // in a four-line Express error handler, the header on one line suppressed
  // both the `none`-algorithm JWT finding and the returned stack trace below
  // it. The failure mode is the dangerous kind — not fewer findings, none, and
  // indistinguishable from clean code.
  //
  // Scoped to the header prefix rather than to a bare `allow(?!-)`, because
  // this guard also runs over `.yml` and `.conf` files, where `allow-list:`
  // and `allowed-hosts:` are ordinary keys that should still guard.
  /(?<!Access-Control-)\ballow(?:ed|list|_list|ed_hosts)?\b|\bwhitelist\b|\b\w{0,6}[Ee]sc(?:ape)?(?:[Hh]tml|HTML|[Xx]ml|XML|[Ss]ql|[Aa]ttr|[Jj]s|[Uu]ri|[Uu]rl)?\s*\(|\bhtml_escape\b|\bhtmlspecialchars\s*\(|\bsanitiz\w*\b|\bencoded\b|\brealpath\b|\bcommonpath\b|\bresolve\(\)\.startsWith\b|\bprocess\.env\b|\bos\.environ\b|\bgetenv\b|\bENV\s*\[|setObjectInputFilter|ObjectInputFilter/i;

/** Evidence that an XML parser factory has been hardened against XXE. */
const XXE_GUARD =
  /FEATURE_SECURE_PROCESSING|setExpandEntityReferences|disallow-doctype-decl|external-general-entities|external-parameter-entities|setXIncludeAware\s*\(\s*false/;

/**
 * Evidence that a Java source parses XML at all.
 *
 * The package names are the reliable half: a file that reaches for
 * `javax.xml.parsers` or `org.xml.sax` has declared its intent at the top,
 * whatever the local variable ends up being called. The bare type names cover
 * sources that import by wildcard or sit in the same package.
 */
const XML_PARSING_FILE =
  /\b(?:javax\.xml|org\.xml\.sax|org\.w3c\.dom|org\.jdom2?|org\.dom4j|XmlPullParser|DocumentBuilderFactory|DocumentBuilder|SAXParserFactory|SAXParser|XMLInputFactory|XMLReaderFactory|XMLReader|SAXBuilder|SAXReader)\b/;

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
// Each verb requires the clause that makes it SQL rather than an English word.
//
// The bare forms — `INSERT`, `UPDATE`, `DELETE`, `DROP`, a lone `SELECT` — were
// the source of this rule's false positives: `\bINSERT\b` matches the `insert`
// in a React key `` `insert-${i}` ``, and `\bUPDATE\b` matches `Update` in a
// log line `` `Update finished in ${ms}ms` ``. Both read as SQL injection.
//
// Real SQL pairs the verb with structure — `SELECT … FROM`, `INSERT INTO`,
// `UPDATE … SET`, `DELETE FROM`, `DROP TABLE`. Requiring it keeps every
// injection shape the corpus and the unit tests exercise (all of which are
// `SELECT … FROM` or `DELETE FROM`) while a verb standing alone as prose no
// longer qualifies. The `SELECT`/`UPDATE` look-aheads stay inside one string
// literal — the character class excludes quotes and backticks — so the clause
// must live in the same statement, not merely somewhere later on the line.
const SQL_KEYWORDS =
  "SELECT\\b(?=[^`'\"\\n]*\\bFROM\\b)" +
  "|INSERT\\s+INTO" +
  "|UPDATE\\b(?=[^`'\"\\n]*\\bSET\\b)" +
  "|DELETE\\s+FROM" +
  "|DROP\\s+(?:TABLE|DATABASE|INDEX|VIEW|SCHEMA)" +
  "|TRUNCATE\\s+TABLE" +
  "|UNION\\s+SELECT";

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
    //
    // The clause alternative anchors the keyword to the *start* of the
    // concatenated fragment, because that is where a clause being appended
    // actually sits: `sql + "WHERE id = " + id`, `sql + " ORDER BY " + col`.
    //
    // Allowing it anywhere in the fragment made the rule read English. `WHERE`
    // and `SET` are ordinary words, and without a leading `\b` they were not
    // even required to be whole ones — "any`where`" and "sub`set`" both
    // matched. A help string reading "lists them anywhere" was reported as
    // critical SQL injection, which is the kind of finding that teaches a team
    // the scanner is not worth reading.
    pattern: new RegExp(
      `${SQL_STRING}\\s*\\+|` +
        `${SQL_STRING}\\s*%\\s*[\\w(]|` +
        `${SQL_STRING}\\s*\\.\\s*format\\s*\\(|` +
        '\\+\\s*(?:"|\')\\s*\\b(?:WHERE|ORDER\\s+BY|VALUES|SET)\\b',
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
    /**
     * Interpolating a column list is not interpolating a value.
     *
     *     const COLS = `tld, user_id, owner_email, price_usd`;
     *     get(`SELECT ${COLS} FROM moshpit_tlds WHERE tld = ?`, [tld]);
     *
     * That query *is* parameterised: every value the caller supplies rides a
     * `?`, and the only thing spliced into the text is a constant written a
     * few lines up. Naming the column list once instead of repeating it in
     * fourteen queries is ordinary hygiene, and it is the shape this rule met
     * most often in practice — one repository produced eighteen findings this
     * way and not one of them could be injected into.
     *
     * The guard resolves the interpolations rather than trusting the shape, so
     * the moment a query mixes a constant with anything else —
     * `` `SELECT ${COLS} FROM t WHERE id = ${req.query.id}` `` — it is reported
     * again. `interpolationsAreConstant` requires *every* `${…}` to resolve.
     */
    constantInterpolationGuard: true,
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
    constantInterpolationGuard: true,
    // Interpolation is common in locally run CLI and installer code. Report
    // command execution as an injection vulnerability only when the nearby
    // code shows a caller-controlled source, rather than treating every
    // internally assembled command as attacker input.
    needsContext: true,
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
    // A call whose whole argv is string literals cannot be injected into.
    // `exec.Command("cmd", "/c", "ver")` reads the Windows version; there is no
    // value in it for an attacker to reach, and the consequence above — that a
    // shell will interpret metacharacters — describes metacharacters nobody can
    // supply. gosec's G204 draws the line in the same place, and this was the
    // single finding a Go project got out of a whole scan before declining the
    // offer, which is an expensive way to report nothing.
    //
    // The guard has to end at the closing paren, so a literal followed by
    // anything else still reports: `"ls " + dir` leaves a `+` before the `)`,
    // `fmt.Sprintf(…)` leaves an identifier, and a bare variable leaves a name.
    // `(?:[^"\\]|\\.)*` rather than `[^"]*` so an escaped quote inside a
    // literal — `"echo \"hi\""` — does not end the literal early and drop the
    // guard on a line it should have covered.
    lineGuard:
      /\bexec\.Command(?:Context)?\s*\(\s*(?:ctx\s*,\s*)?"(?:\/bin\/)?(?:sh|bash|zsh|cmd|powershell)"\s*,\s*"(?:-c|\/c)"\s*(?:,\s*"(?:[^"\\]|\\.)*")*\s*,?\s*\)/,
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
    /**
     * The assignment alternative carries its own exemption, as a lookahead, so
     * that it is decided per assignment rather than per line.
     *
     * A whole-statement assignment of a string with no interpolation and no
     * concatenation carries no data, so it cannot carry attacker data. This was
     * the single largest source of noise: a codebase that builds its UI with
     * innerHTML reports every static heading and spinner as XSS, and a rule
     * that flags 40 safe lines to catch one real one gets switched off.
     *
     * Two things this has to get right, and a `lineGuard` could get neither:
     *
     * A statement ends at its semicolon, not at the newline. Anchoring to `$`
     * held the exemption for `el.innerHTML = '';` alone on a line and dropped
     * it the moment anything followed:
     *
     *     function hide() { out.hidden = true; out.innerHTML = ''; rendered = null; }
     *
     * — the same assignment, clearing a node, reported as high-severity XSS
     * because two neighbours shared its line.
     *
     * And an exemption must not become a line-wide amnesty. A guard is tested
     * against the whole line, so one safe clear would exonerate a real sink
     * beside it:
     *
     *     a.innerHTML = ''; b.innerHTML = userInput;
     *
     * As a lookahead the regex decides at each `=` it reaches, so the first
     * assignment is exempt and the second is still reported.
     *
     * The whitespace after `=` is matched *inside* the lookahead rather than
     * before it. Left outside, `\s*` backtracks to zero width, the lookahead
     * then starts on the space instead of the quote, fails to see a literal,
     * and the negative lookahead succeeds — reinstating every finding the
     * exemption was written to remove.
     */
    pattern:
      /\bdangerouslySetInnerHTML\s*=|\.\s*(?:innerHTML|outerHTML)\s*=(?!\s*(?:'[^'\\\n]*'|"[^"\\\n]*"|`[^`$\\\n]*`)\s*(?:;|$))|\bdocument\s*\.\s*write(?:ln)?\s*\(|\.\s*insertAdjacentHTML\s*\(/,
    sanitizedHtmlGuard: true,
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
    safeRedirectGuard: true,
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
  //
  // Evidence that a file parses XML at all. The XXE rules match on receiver
  // *names* — `builder.parse(is)` is the shape the vulnerability actually takes,
  // and the declared type is rarely on that line — so without this the pattern
  // reads any `.parse()` on anything suffixed Builder, Parser or Reader as XML.
  // In practice that meant a hostname-mask parser (`HostMask.Parser.parse(...)`)
  // was reported as CWE-611 at high severity.
  //
  // An import is the cheapest honest signal: a file that parses XML says so at
  // the top, and one that never mentions XML is not parsing it.
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
    // The suffix alone is not enough — plenty of parsers parse things that are
    // not XML — so `fileRequires` decides whether the file is in scope at all.
    pattern: /\b\w*(?:[Bb]uilder|[Pp]arser|[Rr]eader)\s*\.\s*parse\s*\(/,
    fileRequires: XML_PARSING_FILE,
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
    inherent: true,
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

  // ── Weak crypto: Python ──────────────────────────────────────────────────
  //
  // The generic rules above catch the credential case on the matched line.
  // These cover what they miss in Python, where the security role of a value is
  // set by the enclosing function rather than a same-line assignment — a
  // `random`-drawn token that is *returned*, an MD5 used to *verify* an
  // artifact — and the broken ciphers, which have no safe use at all.
  {
    id: 'py-broken-cipher',
    title: 'broken cipher or ECB mode',
    consequence:
      'DES, RC2, RC4 and Blowfish are broken or too small to rely on, and ECB encrypts identical plaintext blocks to identical ciphertext, so structure in the data survives encryption. None of them provides the confidentiality their use implies.',
    cwe: 'CWE-327',
    severity: 'high',
    languages: ['python'],
    // PyCryptodome/PyCrypto constructors. The mode matters only for AES, whose
    // safe modes (GCM, CTR, CBC) are common — so AES matches solely on ECB,
    // while DES/RC4/Blowfish are broken by the algorithm regardless of mode.
    pattern:
      /\b(?:DES|DES3|ARC2|RC2|ARC4|RC4|Blowfish|XOR)\s*\.\s*new\s*\(|\bAES\s*\.\s*new\s*\([^)\n]*\bMODE_ECB\b/,
    inherent: true,
    guard: false,
  },
  {
    id: 'py-weak-hash',
    title: 'broken hash algorithm',
    consequence:
      'MD5 and SHA-1 have practical collisions, so a digest used for integrity or a signature can be forged to match a value the code trusts.',
    cwe: 'CWE-327',
    severity: 'medium',
    languages: ['python'],
    pattern: /\bhashlib\s*\.\s*(?:md5|sha1)\s*\(/,
    // Python 3.9+ marks a non-security digest — a cache key, an ETag — with
    // `usedforsecurity=False`, which is exactly the "this MD5 is not a security
    // claim" signal, so it exempts the line rather than being flagged.
    lineGuard: /usedforsecurity\s*=\s*False/,
  },
  {
    id: 'py-predictable-random-seed',
    title: 'PRNG seeded from a predictable value',
    consequence:
      'Seeding `random` from the clock or the process id makes its whole sequence reproducible, so anything drawn from it afterwards — a token, an id, a shuffle — can be regenerated by guessing the seed.',
    cwe: 'CWE-338',
    severity: 'high',
    languages: ['python'],
    // A time- or pid-derived seed, which is the predictable kind. A fixed
    // integer seed (`random.seed(42)`) is deliberate reproducibility for tests
    // and simulations, so it is left alone. This needs no credential context:
    // seeding the global PRNG from the clock is a weakness on its own terms,
    // which is why the enclosing function's name — that this engine does not
    // read as evidence anyway — is not consulted.
    pattern:
      /\brandom\s*\.\s*seed\s*\([^)\n]*(?:time\s*\.\s*time|datetime|\.\s*now\s*\(|getpid)/,
    inherent: true,
  },
  {
    id: 'redos-nested-quantifier',
    title: 'regex with nested unbounded quantifiers',
    consequence:
      'Catastrophic backtracking: a crafted input of a few dozen characters pins a CPU core for minutes.',
    cwe: 'CWE-1333',
    severity: 'medium',
    // Scoped, because unscoped this rule reads C as if it were a regex.
    //
    // `(void *)*memptr64` — a cast to a pointer type, then a dereference — is
    // the single most ordinary line in a C file, and it matches the first
    // alternative exactly: `(`, some text, `*`, `)`, `*`. Every `*(char *)*p`
    // in a codebase became a ReDoS finding. Caught on inspektor-gadget, where
    // the rule's one and only hit across 1186 files was a `bpf_probe_read_user`
    // call in an eBPF C program.
    //
    // Scoping is the fix rather than a cleverer pattern: C has no regex
    // literals, so there is nothing here for the rule to find no matter how
    // the pattern is written. `other` also covers C++, Rust and Zig, which
    // share the cast-then-deref spelling.
    languages: ['javascript', 'typescript', 'python', 'ruby', 'go', 'java', 'php'],
    pattern:
      /(?:^|[=(:,]\s*)\/(?:\\.|[^/\\\n])*\([^()\n]*[+*][^()\n]*\)\s*(?:[+*]|\{\d+,\})|\b(?:new\s+RegExp|RegExp|re\.compile|regexp\.(?:Compile|MustCompile)|Pattern\.compile)\s*\(\s*(?:r)?["'][^"'\n]*\([^()\n]*[+*][^()\n]*\)\s*(?:[+*]|\{\d+,\})/,
  },

  // ── Temporary files ──────────────────────────────────────────────────────
  {
    id: 'insecure-temp-file',
    title: 'predictable temporary file path',
    consequence:
      'A predictable name in a world-writable directory is a symlink attack: an attacker pre-creates the path and your process writes through it.',
    cwe: 'CWE-377',
    severity: 'medium',
    // `File.createTempFile` is specifically the safe Java API, and a string
    // containing `/tmp/` is not necessarily a write. Detect unsafe name
    // generators and actual writes to a literal temp path instead. Shell
    // redirections are handled by the shell-specific rule below.
    pattern: new RegExp(
      String.raw`\btempfile\.mktemp\s*\(|\bos\.tmpnam\s*\(|\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|createWriteStream|FileOutputStream|FileWriter|os\.OpenFile|open)\s*\([^\n)]*['"]\/tmp\/[^'"\n]+['"]`,
    ),
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

  // ── Shell ────────────────────────────────────────────────────────────────
  //
  // `shell` was a language the type system knew about and no rule targeted, so
  // a repository written entirely in bash got secret detection and nothing
  // else. Installers, CI helpers and packaging scripts are where a great deal
  // of privileged work actually happens, and they run as whoever invoked them.
  {
    id: 'sh-remote-script-execution',
    title: 'network output piped into a shell',
    consequence:
      'Whatever that URL serves at the moment this runs is executed as the invoking user. There is no version, no signature, and no review — a compromise of the host, or anyone able to answer for it, is a compromise of every machine that runs the script.',
    cwe: 'CWE-494',
    severity: 'high',
    languages: ['shell'],
    // The pipe must be the *next* thing: `curl -o f url && sh f` is a different
    // (and checkable) shape, and `curl url | jq` is not an execution at all.
    pattern: /\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:\/bin\/|\/usr\/bin\/)?(?:ba|da|k|z|a)?sh\b/,
    // This is a supply-chain review item, not proof that the repository is
    // compromised. A literal HTTPS installer URL is capped at medium; it only
    // escalates when nearby evidence shows that input can choose the download.
    guard: false,
    // Installer instructions printed by the script do not execute.  Matching
    // them made a script report its own documentation as a network pipeline.
    lineGuard: /^\s*(?:echo|printf|say|info|warn|error)\s+["'][^"'\n]*\b(?:curl|wget)\b/,
  },
  {
    id: 'sh-eval-expansion',
    title: 'eval on an expanded string',
    consequence:
      'The expansion is re-parsed as shell source, so a `;` or `$(…)` anywhere in the value runs as a command rather than arriving as data.',
    cwe: 'CWE-78',
    severity: 'high',
    languages: ['shell'],
    // Matched against eval's *argument*, not against the rest of the line.
    //
    // `\beval\b.*\$` looks equivalent and is not: bash's ordinary dynamic-range
    // idiom, `eval echo {$((k + 1))..$((k + n))}`, contains `$k` inside the
    // arithmetic, so a line-wide search finds an expansion in a construct that
    // cannot carry a command — `$((…))` is parsed as an expression, where a `;`
    // is a syntax error rather than a second command. That spelling reported
    // 355 findings in one 3,500-line script, all of them the same safe loop.
    //
    // What is left is the form where eval is handed a value directly —
    // `eval "$cmd"`, `eval $cmd`, `eval "$(…)"` — which is the shape that
    // actually re-parses untrusted text as source. `eval echo $x` is not
    // covered; catching it without also catching the range idiom needs to know
    // which expansions are arithmetic, which is parsing, not matching.
    pattern: /\beval\s+(?:-\S+\s+)*(?:"\s*)?\$(?:\{?[A-Za-z_]\w*|\((?!\())/,
    // The shell-init idiom `eval "$(tool init -)"` is the documented interface
    // of most version managers. It is still eval of program output, but the
    // program is a fixed local binary, and flagging it reports every developer
    // dotfile in existence.
    lineGuard:
      /\beval\s+"?\$\(\s*(?:ssh-agent|dircolors|direnv|rbenv|pyenv|nodenv|goenv|jenv|tfenv|opam|luarocks|conda|mamba|zoxide|starship|mise|asdf|fnm|nvm|brew|thefuck|register-python-argcomplete|_\w+_completion)\b/,
  },
  {
    id: 'sh-unquoted-expansion-destructive',
    title: 'unquoted expansion in a destructive command',
    consequence:
      'An unquoted expansion is word-split and glob-expanded before the command sees it. A value with a space removes two paths instead of one; an empty value removes the argument entirely, which is how `rm -rf $DIR/` becomes `rm -rf /`.',
    cwe: 'CWE-78',
    severity: 'high',
    languages: ['shell'],
    // `[^"'\n]*?` cannot cross a quote, so `rm -rf "$dir"` — the correct form —
    // never reaches the `$` and never matches. Only a genuinely bare expansion
    // does. Restricted to recursive/forced removal: a bare `$f` in `rm $f` is
    // sloppy, but it is not the shape that erases a filesystem.
    pattern: /\brm\s+(?:-[a-zA-Z-]*[rRf][a-zA-Z-]*\s+)+[^"'\n]*?\$\{?[A-Za-z_]/,
  },
  {
    id: 'sh-insecure-transport-flag',
    inherent: true,
    title: 'certificate verification disabled',
    consequence:
      'Anyone positioned between this host and the server can substitute the response. When the response is a package, a key or a script, that is remote code execution with the transport doing nothing to stop it.',
    cwe: 'CWE-295',
    severity: 'high',
    languages: ['shell'],
    pattern:
      /\b(?:curl|wget)\b[^\n|]*(?:\s-k(?=\s|$)|\s--insecure\b|\s--no-check-certificate\b)/,
    // Over plain HTTP there is no certificate to skip, so the flag is inert and
    // this rule has nothing to say — `sh-plaintext-download` is the finding
    // that fits. Reporting both put two entries on one line, one of which
    // recommended a fix that would change nothing.
    lineGuard: /^(?!.*https:\/\/).*\bhttp:\/\//,
  },
  {
    id: 'sh-plaintext-download',
    inherent: true,
    title: 'download over plain HTTP',
    consequence:
      'The response arrives unauthenticated over a channel any intermediary can rewrite. Where the payload is an archive, a package list or a key, substituting it is straightforward and leaves nothing for the script to notice.',
    cwe: 'CWE-319',
    severity: 'high',
    languages: ['shell'],
    pattern: /\b(?:curl|wget)\b[^\n|]*\bhttp:\/\//,
    // Loopback and link-local are not carried over a network anyone can sit on.
    lineGuard:
      /http:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|169\.254\.|host\.docker\.internal)\b/,
  },
  {
    id: 'sh-world-writable-permissions',
    inherent: true,
    title: 'world-writable permissions',
    consequence:
      'Any local account can rewrite the file. If it is a script, a config or anything on a privileged path, the next process to read it runs someone else’s content.',
    cwe: 'CWE-732',
    severity: 'medium',
    languages: ['shell'],
    pattern: /\bchmod\s+(?:-[a-zA-Z-]+\s+)*(?:0?777|a\+rwx|ugo\+rwx|a=rwx)\b/,
  },
  {
    id: 'sh-predictable-temp-path',
    title: 'predictable temporary file',
    consequence:
      'The name is guessable, so a local attacker can create it first — as a symlink to somewhere that matters — and the script writes through it with its own privileges.',
    cwe: 'CWE-377',
    severity: 'medium',
    languages: ['shell'],
    // Redirection or an explicit write into a literal `/tmp` path. A `$$` or
    // `$RANDOM` suffix is still predictable, so it is not treated as a fix;
    // `mktemp` is, and it is the guard below.
    pattern: /(?:>{1,2}\s*|\b(?:tee|touch|cp|mv|install)\s+(?:-\S+\s+)*)\/tmp\/[\w.$-]+/,
    guard: /\bmktemp\b/,
    guardBack: 6,
    guardForward: 2,
  },

  // ── PHP ──────────────────────────────────────────────────────────────────
  //
  // `php` was the second language in `ScanLanguage` that no rule targeted, for
  // the same reason `shell` was: nothing checks the two lists against each
  // other. `LANGUAGE_COVERAGE` in the tests does now.
  {
    id: 'php-sql-interpolation',
    title: 'SQL assembled by interpolation',
    consequence:
      'PHP interpolates variables inside double-quoted strings, so the value is part of the statement before the driver ever sees it. A quote in the value ends the literal and the rest is parsed as SQL.',
    cwe: 'CWE-89',
    severity: 'critical',
    languages: ['php'],
    // Interpolation (`"… $id …"`, `"… {$id} …"`) or concatenation onto a SQL
    // string. A prepared statement passes placeholders and binds separately,
    // so its query string contains neither.
    pattern: new RegExp(
      `\\b(?:mysqli_query|mysql_query|pg_query|->\\s*(?:query|exec|unprepared))\\s*\\([^)]*(?:"[^"\\n]*(?:${SQL_KEYWORDS})\\b[^"\\n]*(?:\\$\\w+|\\{\\$)|${SQL_STRING}\\s*\\.)`,
      'i',
    ),
  },
  {
    id: 'php-shell-exec-interpolation',
    title: 'shell command built from a variable',
    consequence:
      'The string is handed to `/bin/sh`, which interprets `;`, `|` and `$(…)` in whatever the variable held.',
    cwe: 'CWE-78',
    severity: 'critical',
    languages: ['php'],
    pattern:
      /\b(?:exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:"[^"\n]*(?:\$\w+|\{\$)|'[^'\n]*'\s*\.|\$\w+\s*\.)/,
    // `escapeshellarg`/`escapeshellcmd` are the correct answer and are usually
    // applied inline, so a line-scoped guard is the right shape.
    lineGuard: /\bescapeshell(?:arg|cmd)\s*\(/,
  },
  {
    id: 'php-dynamic-code-execution',
    title: 'dynamic code execution',
    consequence:
      'Whatever reaches this call is executed as PHP source with the privileges of the web process.',
    cwe: 'CWE-95',
    severity: 'critical',
    languages: ['php'],
    pattern: /\b(?:eval|assert|create_function)\s*\(\s*(?:\$\w+|"[^"\n]*(?:\$\w+|\{\$))/,
    guard: false,
  },
  {
    id: 'php-dynamic-file-inclusion',
    title: 'include path built from a variable',
    consequence:
      'The included file is executed, not read. A traversal sequence reaches any file the process can open, and with a remote wrapper enabled the path need not be local at all.',
    cwe: 'CWE-98',
    severity: 'critical',
    languages: ['php'],
    pattern:
      /\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?(?:\$\w+|"[^"\n]*(?:\$\w+|\{\$)|'[^'\n]*'\s*\.)/,
    // A basename-and-allow-list is the standard fix; `basename` alone still
    // leaves the extension open, but it defeats traversal, which is the part
    // this rule is about.
    lineGuard: /\bbasename\s*\(/,
  },
  {
    id: 'php-unserialize-untrusted',
    title: 'unserialize on request data',
    consequence:
      'PHP object deserialisation instantiates classes and runs their magic methods. With a suitable class in scope this is remote code execution, and no `unserialize` option short of `allowed_classes => false` prevents it.',
    cwe: 'CWE-502',
    severity: 'critical',
    languages: ['php'],
    pattern: /\bunserialize\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)\b|\$\w+)/,
    // The key is an array key and is normally quoted: `['allowed_classes' => false]`.
    lineGuard: /["']?allowed_classes["']?\s*=>\s*(?:false|\[)/,
    needsContext: true,
  },
  {
    id: 'php-unescaped-output',
    title: 'request data echoed without escaping',
    consequence:
      'The value is written into the response verbatim, so markup in it becomes markup in the page — script that runs with the victim’s session.',
    cwe: 'CWE-79',
    severity: 'high',
    languages: ['php'],
    pattern:
      /\b(?:echo|print)\s+[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b|<\?=\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
  },
  {
    id: 'php-request-path-traversal',
    title: 'file path taken from the request',
    consequence:
      'A `../` sequence in the value walks out of the intended directory, and the process reads or writes wherever it lands.',
    cwe: 'CWE-22',
    severity: 'high',
    languages: ['php'],
    pattern:
      /\b(?:file_get_contents|file_put_contents|fopen|readfile|unlink|copy|rename|opendir|scandir)\s*\(\s*[^)\n]*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
    lineGuard: /\bbasename\s*\(|\brealpath\s*\(/,
  },
  {
    id: 'php-variable-injection',
    title: 'request data expanded into local variables',
    consequence:
      '`extract` creates a variable per key, so a request can overwrite any local already in scope — including the one a subsequent authorisation check reads.',
    cwe: 'CWE-621',
    severity: 'high',
    languages: ['php'],
    pattern: /\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b|\bimport_request_variables\s*\(/,
    guard: false,
  },

  // ── Java and Go: classes the other languages already had ─────────────────
  //
  // Command injection, SSRF and path traversal were implemented for JavaScript
  // and, in part, for Go, and never for Java — so the same defect in the same
  // codebase was reported or not depending on which file it lived in. TLS
  // verification, weak hashing and insecure randomness are deliberately absent
  // here: `tls-verification-disabled`, `weak-hash-on-credential` and
  // `insecure-randomness-for-secret` are language-agnostic and already cover
  // both, including Go's `InsecureSkipVerify` and Java's `MessageDigest`.
  {
    id: 'java-runtime-exec-concatenation',
    title: 'Runtime.exec with a concatenated command',
    consequence:
      'The single-string form of `exec` is split on whitespace and handed to the OS. A value carrying a space becomes extra arguments, and where a shell is invoked, `;` and `$(…)` become extra commands.',
    cwe: 'CWE-78',
    severity: 'critical',
    languages: ['java'],
    // The array form — `exec(new String[]{"git", arg})` — passes argv and is
    // the fix, so it is not matched: the `+` has to be inside the string
    // argument for this to fire.
    pattern:
      /\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder)\s*\(\s*(?:"[^"\n]*"\s*\+|\w+\s*\+\s*")/,
  },
  {
    id: 'java-ssrf-outbound-request',
    title: 'outbound request to a computed URL',
    consequence:
      'The destination is chosen by the caller, so the request can be aimed at internal services and cloud metadata endpoints that are reachable from this host and from nowhere else.',
    cwe: 'CWE-918',
    severity: 'high',
    languages: ['java'],
    pattern:
      /\bnew\s+URL\s*\(\s*(?!\s*"[a-z]+:\/\/[^"\n]*"\s*\))[^)\n]*\w|\bHttpRequest\s*\.\s*newBuilder\s*\(\s*\)\s*\.\s*uri\s*\(\s*URI\s*\.\s*create\s*\(\s*[^"\n)]/,
    needsContext: true,
  },
  {
    id: 'java-request-path-traversal',
    title: 'file path built from request data',
    consequence:
      'A `../` sequence in the value walks out of the intended directory. The process then reads or writes wherever it lands, with its own privileges.',
    cwe: 'CWE-22',
    severity: 'high',
    languages: ['java'],
    pattern:
      /\b(?:new\s+File|new\s+FileInputStream|new\s+FileOutputStream|Paths\s*\.\s*get|Files\s*\.\s*(?:readAllBytes|newInputStream|newOutputStream|copy|delete))\s*\([^)\n]*\+/,
    // `getCanonicalPath().startsWith(base)` is the check that makes this safe,
    // and it is normally a line or two below the construction.
    guard: /getCanonicalPath|toRealPath|normalize\s*\(\s*\)|\bstartsWith\s*\(/,
    guardForward: 4,
    needsContext: true,
  },
  {
    id: 'java-broken-cipher',
    inherent: true,
    title: 'broken cipher or ECB mode',
    consequence:
      'DES, RC2, RC4 and Blowfish are broken or too small to rely on. ECB encrypts identical plaintext blocks to identical ciphertext blocks, so structure in the data survives encryption and is readable straight off the ciphertext.',
    cwe: 'CWE-327',
    severity: 'high',
    languages: ['java'],
    // Bare `"AES"` is included: the JCE resolves it to `AES/ECB/PKCS5Padding`,
    // so the default is the mode this rule exists to catch.
    pattern:
      /\bCipher\s*\.\s*getInstance\s*\(\s*"(?:DES|DESede|RC2|RC4|ARCFOUR|Blowfish)(?:\/|")|\bCipher\s*\.\s*getInstance\s*\(\s*"[^"\n]*\/ECB\/|\bCipher\s*\.\s*getInstance\s*\(\s*"AES"\s*\)/,
    guard: false,
  },
  {
    id: 'go-request-path-traversal',
    title: 'file path built from request data',
    consequence:
      'A `../` sequence in the value walks out of the intended directory, and the handler serves or writes whatever it reaches.',
    cwe: 'CWE-22',
    severity: 'high',
    languages: ['go'],
    pattern:
      /\b(?:os\s*\.\s*(?:Open|OpenFile|ReadFile|Create|Remove|WriteFile)|ioutil\s*\.\s*(?:ReadFile|WriteFile)|http\s*\.\s*ServeFile)\s*\([^)\n]*(?:r\s*\.\s*URL|FormValue|Query\s*\(\s*\)\s*\.\s*Get|mux\s*\.\s*Vars|\bfilepath\s*\.\s*Join\s*\([^)\n]*\w)/,
    // `filepath.Clean` alone does not bound the result to a directory, so it is
    // not a guard here — the containment check is.
    guard: /\bstrings\s*\.\s*HasPrefix\s*\(|\bfilepath\s*\.\s*Rel\s*\(|\bfs\s*\.\s*ValidPath\s*\(|\bhttp\s*\.\s*Dir\b/,
    guardBack: 5,
    guardForward: 3,
    needsContext: true,
  },
  {
    id: 'go-template-escaping-bypass',
    title: 'value marked as pre-escaped HTML',
    consequence:
      '`template.HTML` tells `html/template` the value is already safe, which switches off the contextual escaping that makes the package worth using. Markup in the value reaches the page intact.',
    cwe: 'CWE-79',
    severity: 'high',
    languages: ['go'],
    // A conversion of a *variable*. `template.HTML("<br>")` on a literal is a
    // constant the author wrote and is not a finding.
    pattern: /\btemplate\s*\.\s*(?:HTML|JS|CSS|HTMLAttr|URL|Srcset)\s*\(\s*(?!\s*[`"])/,
    needsContext: true,
  },

  // ── Misconfiguration, weak crypto and the rest of the injection family ────
  //
  // Each of these is a defect the *line* shows — a debug flag left on, a
  // wildcard CORS origin, a key literal, a fast password hash — so the safe
  // counterpart in the corpus differs on something visible here, not three
  // functions away. The classes that genuinely need whole-function reasoning
  // (CSRF, IDOR, TOCTOU, missing authorization) are deliberately still absent;
  // see KNOWN_GAPS.
  {
    id: 'py-framework-debug-enabled',
    title: 'debug mode enabled',
    consequence:
      'Framework debug mode serves an interactive traceback console on any error — arbitrary code execution to whoever triggers it — and leaks source and configuration.',
    cwe: 'CWE-489',
    severity: 'high',
    languages: ['python'],
    pattern: /\bDEBUG['"\]]*\s*[=:]\s*True\b|\.\s*run\s*\([^)\n]*\bdebug\s*=\s*True\b/,
    inherent: true,
  },
  {
    id: 'js-cors-wildcard-credentials',
    title: 'wildcard CORS origin with credentials',
    consequence:
      'A `*` origin combined with credentials lets any site read authenticated responses on the victim’s behalf: the browser attaches their cookies and hands the result to the attacker’s page.',
    cwe: 'CWE-942',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern:
      /origin\s*:\s*['"`]\*['"`][^\n]*credentials\s*:\s*true|credentials\s*:\s*true[^\n]*origin\s*:\s*['"`]\*['"`]/,
    inherent: true,
  },
  {
    id: 'js-cookie-insecure-flag',
    title: 'cookie set with Secure disabled',
    consequence:
      'Without Secure the cookie travels over plain HTTP, where anyone on the path reads it. A session cookie set this way is a session anyone can lift.',
    cwe: 'CWE-614',
    severity: 'medium',
    languages: ['javascript', 'typescript'],
    pattern: /\.\s*cookie\s*\([^\n]*\bsecure\s*:\s*false\b/i,
  },
  {
    id: 'js-hardcoded-crypto-key',
    title: 'hardcoded key material',
    consequence:
      'A key committed to source is a key everyone with the repo has. The encryption it backs protects nothing once the source is shared, forked or leaked.',
    cwe: 'CWE-321',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern: /\b(?:key|secret|iv|passphrase|salt|hmac)\w*\s*=\s*Buffer\s*\.\s*from\s*\(\s*['"`]/i,
    fileRequires: /\bcrypto\b|createCipheriv|createDecipheriv|createHmac/,
  },
  {
    id: 'py-hardcoded-secret-key',
    title: 'hardcoded application secret',
    consequence:
      'A signing secret in source lets anyone with the code forge what it signs — session cookies, tokens, password-reset links.',
    cwe: 'CWE-798',
    severity: 'high',
    languages: ['python'],
    // Assigned a *string literal*. A value from a provider call (`os.environ`,
    // `secret_provider(...)`) is the correct shape and starts with an
    // identifier after the `=`, not a quote.
    pattern:
      /\b(?:SECRET_KEY|JWT_SECRET|SIGNING_KEY|SESSION_SECRET|PRIVATE_KEY)['"\]]*\s*[=:]\s*['"`][^'"`\n]{6,}/,
  },
  {
    id: 'py-ldap-injection',
    title: 'LDAP filter built by interpolation',
    consequence:
      'Unescaped input in an LDAP filter lets an attacker rewrite the query — widening a match, bypassing a check, or enumerating the directory.',
    cwe: 'CWE-90',
    severity: 'high',
    languages: ['python'],
    // An f-string whose content is an LDAP filter (`(&…` / `(|…`) with an
    // interpolation. One variant per quote so an inner `'` inside a `"`-string
    // does not end the class early.
    pattern: /\bf"[^"\n]*\([&|][^"\n]*\{[^}\n]+\}|\bf'[^'\n]*\([&|][^'\n]*\{[^}\n]+\}/,
    // The guard is an escaper *call*, not the mere presence of `escape` — the
    // module-level `from ldap.filter import escape_filter_chars` sits in every
    // window and would otherwise exonerate the unescaped filter too.
    guard: /\bescape\w*\s*\(/i,
  },
  {
    id: 'py-xpath-injection',
    title: 'XPath built by interpolation',
    consequence:
      'Unescaped input in an XPath expression lets an attacker rewrite the query and read nodes it was meant to exclude.',
    cwe: 'CWE-643',
    severity: 'high',
    languages: ['python'],
    // Per-quote, so an inner `'` in a `"`-delimited f-string (`text()='{x}'`)
    // does not truncate the match before the interpolation.
    pattern:
      /\bf"[^"\n]*(?:\/\/|\/\w+\[)[^"\n]*\{[^}\n]+\}|\bf'[^'\n]*(?:\/\/|\/\w+\[)[^'\n]*\{[^}\n]+\}/,
  },
  {
    id: 'py-fast-password-hash',
    title: 'password hashed with a fast digest',
    consequence:
      'SHA-2 is built to be fast, which is exactly wrong for a password: a leaked hash is brute-forced at billions of guesses a second. Passwords need a slow, salted KDF (bcrypt, scrypt, argon2, PBKDF2).',
    cwe: 'CWE-759',
    severity: 'high',
    languages: ['python'],
    pattern:
      /\bhashlib\s*\.\s*(?:sha224|sha256|sha384|sha512)\s*\([^)\n]*(?:password|passwd|passphrase|pwd)/i,
    guard: /pbkdf2|scrypt|bcrypt|argon/i,
  },
  {
    id: 'py-plaintext-password-retained',
    title: 'plaintext password stored',
    consequence:
      'A record that keeps the password itself, not a hash, turns one database leak into every user’s credential — reused across every other site they log into.',
    cwe: 'CWE-256',
    severity: 'high',
    languages: ['python'],
    pattern: /['"]password['"]\s*:\s*(?:form|request|req|data|payload|body|params)\b/i,
  },
  {
    id: 'js-timing-unsafe-mac-compare',
    title: 'MAC or signature compared with ==',
    consequence:
      '`===` on a signature returns the moment a byte differs, so response time leaks how much of a forged signature is correct — enough to recover a valid one byte by byte. Use `crypto.timingSafeEqual`.',
    cwe: 'CWE-208',
    severity: 'medium',
    languages: ['javascript', 'typescript'],
    pattern:
      /\b\w*(?:[Ss]ignature|[Hh]mac|[Dd]igest)\s*===?\s*\w|\w\s*===?\s*\w*(?:[Ss]ignature|[Hh]mac|[Dd]igest)\b/,
    // Comparing `.length` is the *safe* preamble to a constant-time check, not
    // the timing-unsafe value comparison this rule is about — and the
    // `timingSafeEqual` that follows it sits forward of the line, out of the
    // backward guard window.
    lineGuard: /\.\s*length\b/,
    guard: /timingSafeEqual/,
  },
  {
    id: 'js-predictable-cipher-iv',
    title: 'static initialization vector',
    consequence:
      'A fixed IV reused across encryptions leaks whether two plaintexts are equal and, in CBC/CTR, breaks confidentiality outright. The IV must be random per message.',
    cwe: 'CWE-329',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern: /\b\w*[Ii][Vv]\s*=\s*Buffer\s*\.\s*(?:alloc|from)\s*\(/,
    fileRequires: /createCipheriv|\bcrypto\b/,
    guard: /randomBytes|randomFill/,
  },
  // A rule for `Math.random().toString(36)` was tried and dropped: the exact
  // shape generates security tokens *and* benign callback/correlation ids
  // (Capacitor's native bridge uses it for the latter), with no line-visible
  // signal between them. The credential-scoped `insecure-randomness-for-secret`
  // above still catches the `token = …Math.random…` case; the bare shape is
  // left alone rather than flagged on every id generator.
  {
    id: 'js-mass-assignment',
    title: 'mass assignment from request data',
    consequence:
      'Copying the whole request body onto a record lets a caller set fields you never exposed — `isAdmin`, `role`, `balance` — because nothing stands between the input and the object.',
    cwe: 'CWE-915',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern:
      /\bObject\s*\.\s*assign\s*\([^,\n]+,\s*(?:req|request|ctx)\s*\.\s*(?:body|query|params)\b/,
  },
  {
    id: 'js-header-injection',
    title: 'response header set from request input',
    consequence:
      'A CR/LF in the value splits the response — the attacker injects headers or a whole second response (cache poisoning, a forged Set-Cookie).',
    cwe: 'CWE-113',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern:
      /\.\s*(?:setHeader|header|set)\s*\(\s*['"`][^'"`\n]+['"`]\s*,\s*(?:req|request|ctx)\s*\.\s*(?:query|body|params|headers)\b/,
  },
  {
    id: 'js-nosql-injection',
    title: 'NoSQL query built from request data',
    consequence:
      'A request object passed straight to `find`/`update` lets the caller supply MongoDB operators — `{"$ne": null}`, `{"$gt": ""}`, `{"$where": "…"}` — turning a lookup into an authentication bypass or arbitrary query.',
    cwe: 'CWE-943',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern:
      /\.\s*(?:find|findOne|findOneAndUpdate|updateOne|updateMany|update|deleteOne|deleteMany|remove|count|countDocuments|aggregate)\s*\(\s*(?:req|request|ctx)\s*\.\s*(?:body|query|params)\b/,
  },
  {
    id: 'js-host-header-trust',
    title: 'URL built from the Host header',
    consequence:
      'The Host header is attacker-controlled. Building a link from it — a password-reset URL above all — lets an attacker point the victim’s reset token at a domain they control.',
    cwe: 'CWE-346',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern:
      /\$\{[^}\n]*\breq(?:uest)?\s*\.\s*(?:headers\s*\.\s*host|hostname|host)\b|['"`]\s*\+\s*req(?:uest)?\s*\.\s*(?:headers\s*\.\s*host|hostname)\b/,
    /**
     * Parsing the request's own URL is not building a link from the Host
     * header, even though it is spelled with one.
     *
     *     const url = new URL(request.url, `http://${request.headers.host}`);
     *     const token = url.searchParams.get('token');
     *
     * `request.url` on a Node server is a path — `/ws?token=…` — and `new URL`
     * refuses a relative input without a base. The base exists to satisfy the
     * parser and is thrown away; only the path and query are ever read. Every
     * Node HTTP handler that wants a query parameter is written this way, so
     * the rule fired on the framework idiom rather than on the defect.
     *
     * Narrow on purpose: the first argument must be `req.url` itself. The
     * dangerous shape passes a *path* the application chose —
     * `new URL('/reset?t=…', `https://${req.headers.host}`)` — and that is what
     * produces an attacker-controlled link. It does not match this guard.
     */
    lineGuard: /\bnew\s+URL\s*\(\s*(?:req|request|ctx)(?:uest)?\s*\.\s*url\b\s*,/,
  },
  // A recursive-merge prototype-pollution rule (`target[key] = source[key]`
  // with no `__proto__` guard) was built and dropped. The bare copy-by-key is
  // the safe allow-listed shape (`updates[field] = body[field]` over an
  // `allowedFields` list) as often as the vulnerable one; whether it is a sink
  // depends on where the key comes from and which of endless guard idioms
  // filters it — a whole-function question this line-oriented engine does not
  // answer. It flagged legitimate merges in Capacitor and in this repo's own
  // web app. `js-prototype-pollution` still catches the explicit `__proto__`
  // literal; the recursive-merge case is left to KNOWN_GAPS.

  // Node-ecosystem classes — vm2, Electron, JWT, archive extraction, headless
  // browsers — are kept in their own table because each has to know which
  // package it is looking at before it can claim anything. Folded in here so
  // there stays exactly one rule list for every consumer to iterate.
  ...NODE_RULES,
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

/**
 * Whole-file text, memoised on the `lines` array it came from.
 *
 * `fileRequires` asks a question no window can answer, but joining the file on
 * every line of every rule would make scanning quadratic in file length. The
 * caller already reuses one `lines` array for the whole file, so keying on its
 * identity gives one join per file. A `WeakMap` keeps nothing alive after the
 * file is done with.
 */
const FILE_TEXT = new WeakMap<readonly string[], string>();

function fileTextOf(lines: readonly string[]): string {
  let text = FILE_TEXT.get(lines);
  if (text === undefined) {
    text = lines.join('\n');
    FILE_TEXT.set(lines, text);
  }
  return text;
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
/**
 * Blank out single-quoted spans before looking for untrusted input.
 *
 * The shell performs no expansion inside single quotes, so a `$1` there is the
 * two characters `$1` and never a positional parameter. Without this, an awk
 * or sed program written inline — `gawk -F '=' '{print $2}'` — reads as
 * attacker-controlled input.
 *
 * That was not theoretical. In `ralyodio/debtap` it escalated one `curl -k`
 * line to `contextual`, and the ±6-line window carried the escalation to four
 * neighbouring findings, so the same defect reported `high` on lines 103–111
 * and `medium` on 113, 120 and 128 — decided entirely by distance from an awk
 * one-liner. A `--fail-on high` gate would have caught five of eight identical
 * problems.
 */
function withoutSingleQuoted(text: string): string {
  return text.replace(/'[^'\n]*'/g, "''");
}

/**
 * The callees of every call still open at the start of this line.
 *
 * A bracket walk over the preceding window, skipping string bodies so that a
 * parenthesis inside a message — `log('oops :(')` — does not unbalance it.
 * Returned outermost-first; a rule usually only cares whether *any* of them
 * matches.
 *
 * The walk starts mid-file, so a `)` closing a call opened before the window
 * pops an empty stack. That direction is safe: it can only lose an enclosing
 * name, never invent one, and a lost name means the finding is still reported.
 */
/**
 * The dotted name immediately left of `open`, walking backwards from it.
 *
 * A backwards scan rather than `/([\w$.]*)\s*$/` over `text.slice(0, open)`:
 * the slice copies the whole prefix and the match rescans it, once per
 * parenthesis, which is quadratic on a long window for an answer that is
 * always the last few characters.
 */
function calleeEndingAt(text: string, open: number): string {
  let end = open;
  while (end > 0 && (text[end - 1] === ' ' || text[end - 1] === '\t')) end -= 1;
  let start = end;
  while (start > 0 && /[\w$.]/.test(text[start - 1]!)) start -= 1;
  return text.slice(start, end);
}

export function enclosingCallees(
  lines: readonly string[],
  index: number,
  back: number,
): string[] {
  const before = lines.slice(Math.max(0, index - back), index).join('\n');
  const stack: string[] = [];
  let quote: string | null = null;

  for (let i = 0; i < before.length; i += 1) {
    const ch = before[i]!;
    if (quote) {
      if (ch === '\\') i += 1;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') quote = ch;
    else if (ch === '(') stack.push(calleeEndingAt(before, i));
    else if (ch === ')') stack.pop();
  }
  return stack;
}

/**
 * Every `${…}` on the line, or `null` if there are none to account for.
 *
 * Scanned rather than matched. The obvious `/\$\{([^}]*)\}/g` is polynomial —
 * on a line of many unclosed `${`, each start position rescans to the end —
 * and a scanner that can be stalled by the file it is reading is a denial of
 * service in a CI gate. This repository reports that class as
 * `redos-nested-quantifier`; it should not ship it.
 *
 * `null` for an unterminated `${`, which is the safe direction: the caller
 * exonerates only when it can account for *every* interpolation, so refusing
 * to answer leaves the finding reported.
 */
function interpolations(line: string): string[] | null {
  const found: string[] = [];
  for (let i = 0; ; ) {
    const start = line.indexOf('${', i);
    if (start === -1) break;
    const end = line.indexOf('}', start + 2);
    if (end === -1) return null;
    found.push(line.slice(start + 2, end).trim());
    i = end + 1;
  }
  return found.length > 0 ? found : null;
}

/** Is `name` bound in this file to a `const` holding a plain string literal? */
function isConstantString(name: string, fileText: string): boolean {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    `\\bconst\\s+${escaped}\\s*(?::[^=\\n]+)?=\\s*(?:'[^'\\n]*'|"[^"\\n]*"|\`[^\`$\\n]*\`)`,
  ).test(fileText);
}

/**
 * Is a `dangerouslySetInnerHTML` value explicitly made safe on this line, or
 * a `const` whose sole binding was made safe earlier in the file?
 *
 * This intentionally recognises only explicit sanitizer/escaper names. It
 * does not treat a variable called `html` as trustworthy; the source must
 * visibly pass through an operation whose contract is HTML-safe output.
 */
function hasSanitizedHtmlValue(line: string, fileText: string): boolean {
  const direct = /\b__html\s*:\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)?(?:sanitize\w*|escape\w*|serializeJsonForHtml|renderSanitizedMarkdown)\s*\(/i;
  if (direct.test(line)) return true;

  const value = /\b__html\s*:\s*([A-Za-z_$][\w$]*)\b/.exec(line)?.[1];
  if (!value) return false;

  const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    `\\bconst\\s+${escaped}\\s*=[^\\n;]*(?:[A-Za-z_$][\\w$]*\\s*\\.\\s*)?(?:sanitize\\w*|escape\\w*|serializeJsonForHtml|renderSanitizedMarkdown)\\s*\\(`,
    'i',
  ).test(fileText);
}

function isIdentifierStart(char: string | undefined): boolean {
  if (!char) return false;
  const code = char.charCodeAt(0);
  return char === '$' || char === '_' || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

function isIdentifierPart(char: string | undefined): boolean {
  if (isIdentifierStart(char)) return true;
  if (!char) return false;
  const code = char.charCodeAt(0);
  return code >= 48 && code <= 57;
}

function identifierAfter(text: string, start: number): string | null {
  let index = start;
  while (text[index] === ' ' || text[index] === '\t') index += 1;
  if (!isIdentifierStart(text[index])) return null;
  const from = index;
  while (isIdentifierPart(text[index])) index += 1;
  return text.slice(from, index);
}

/** Does the redirected variable come from an explicit local-path validator? */
function hasSafeRedirectValue(line: string, fileText: string): boolean {
  const location = line.indexOf('window.location');
  const redirect = line.indexOf('.redirect');
  const valueStart = location >= 0
    ? line.indexOf('=', location) + 1
    : redirect >= 0
      ? line.indexOf('(', redirect) + 1
      : 0;
  if (valueStart === 0) return false;

  const value = identifierAfter(line, valueStart);
  if (!value) return false;

  const declaration = `const ${value}`;
  for (const candidate of fileText.split('\n')) {
    const at = candidate.indexOf(declaration);
    if (at === -1 || isIdentifierPart(candidate[at - 1]) || isIdentifierPart(candidate[at + declaration.length])) {
      continue;
    }
    const equals = candidate.indexOf('=', at + declaration.length);
    const initializer = candidate.slice(equals + 1);
    if (
      equals !== -1 &&
      ['safeRedirectPath(', 'safeRedirectUrl(', 'safeRedirectURL('].some((call) => initializer.includes(call))
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Does every interpolation on this line resolve to a file-local constant?
 *
 * False when there are no interpolations at all: the concatenation spellings
 * of the same rules (`exec('cmd ' + arg)`) have nothing to resolve and must
 * stay reported.
 */
export function interpolationsAreConstant(line: string, fileText: string): boolean {
  const found = interpolations(line);
  if (!found) return false;
  return found.every(
    (expr) => /^[A-Za-z_$][\w$]*$/.test(expr) && isConstantString(expr, fileText),
  );
}

/**
 * How far below an allocation a fill is still credibly *the* fill for it.
 *
 * Sixteen because the shape that motivated this is a ring-buffer read: the
 * allocation, an early return for the empty case, three or four lines working
 * out the wrap-around offsets, then the copies. Ten lines was not enough for
 * it. Past this the write is more likely to belong to something else, and the
 * finding should stand.
 */
const FILL_LOOKAHEAD = 16;

/**
 * An identifier, matched only where one can actually begin.
 *
 * The lookbehind is load-bearing rather than decoration. `[A-Za-z_$][\w$]*`
 * can start at *every* position inside a run of `$`, so a long run costs a
 * restart per character and the match is quadratic in line length. This
 * repository reports that class as `redos-nested-quantifier` and CodeQL
 * reports it as `js/polynomial-redos`; it should not ship it.
 */
const NAME = String.raw`(?<![\w$])([A-Za-z_$][\w$]*)`;

const ALLOCATION_BINDING = new RegExp(
  `${NAME}\\s*=\\s*(?:new\\s+Buffer\\s*\\(|Buffer\\s*\\.\\s*allocUnsafe(?:Slow)?\\s*\\()`,
);

/**
 * The name an uninitialised allocation on this line is bound to, if any.
 *
 * Declarations and plain assignments both. A property target such as
 * `this.buf = Buffer.allocUnsafe(n)` reduces to `buf`, which is how the writes
 * that follow will spell it.
 */
function allocationBinding(line: string): string | null {
  return ALLOCATION_BINDING.exec(line)?.[1] ?? null;
}

/**
 * The spellings that write into a buffer: copied into as a destination, filled
 * or written through its own methods, `set` from a typed array, or assigned
 * per index.
 *
 * Fixed patterns that *capture* a name, rather than a pattern built by
 * interpolating the binding into `new RegExp`. The first version did the
 * latter and went wrong three ways at once — the name had to be escaped, the
 * escaper missed backslashes, and the constructed pattern was itself
 * polynomial on a name of many `$`. All three stop existing once the name is
 * compared as a string instead of spliced into a regex.
 */
const WRITE_SHAPES: readonly RegExp[] = [
  // `src.copy(name, …)` — name is the destination.
  /\.\s*copy\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]/g,
  // `name.fill(…)`, `name.write*(…)`, `name.set(…)`.
  new RegExp(`${NAME}\\s*\\.\\s*(?:fill|set|write[A-Za-z0-9]*)\\s*\\(`, 'g'),
  // `name[i] = …`, but not `name[i] === …`.
  new RegExp(`${NAME}\\s*\\[[^\\]\\n]*\\]\\s*=(?!=)`, 'g'),
];

/** Does anything in `text` write into the buffer bound to `name`? */
function writesInto(text: string, name: string): boolean {
  for (const shape of WRITE_SHAPES) {
    // Module-level and `g`, so the cursor from the previous call is still on
    // it. Reset before use rather than allocating a regex per line.
    shape.lastIndex = 0;
    for (let found = shape.exec(text); found !== null; found = shape.exec(text)) {
      if (found[1] === name) return true;
    }
  }
  return false;
}

/**
 * True when the buffer allocated on this line is filled before it escapes.
 *
 * Looks forward only. Code that fills a buffer runs after the allocation, by
 * definition — there is nothing above it to find.
 */
export function bufferFilledBeforeUse(ctx: MatchContext): boolean {
  const line = ctx.lines[ctx.index] ?? '';

  // `Buffer.allocUnsafe(n).fill(0)` — filled in the same breath, and there is
  // no binding to follow because none is needed.
  if (/\ballocUnsafe(?:Slow)?\s*\([^)\n]*\)\s*\.\s*fill\s*\(/.test(line)) return true;

  const name = allocationBinding(line);
  if (!name) return false;

  // The allocation line itself first: `const b = Buffer.allocUnsafe(n); b.fill(0);`
  // is one line, and a rule that missed it would be answering a question about
  // formatting rather than about the code. Only the part after the `=`, so the
  // binding on the left is not read as a write to itself.
  if (writesInto(line.slice(line.indexOf('=') + 1), name)) return true;

  const last = Math.min(ctx.lines.length - 1, ctx.index + FILL_LOOKAHEAD);
  for (let i = ctx.index + 1; i <= last; i += 1) {
    const next = ctx.lines[i] ?? '';
    if (skippable(next, i, ctx.prose)) continue;
    if (writesInto(next, name)) return true;
  }
  return false;
}

export function evaluateRule(rule: CodeRule, ctx: MatchContext): RuleMatch | null {
  if (rule.languages && !rule.languages.includes(ctx.language)) return null;

  const line = ctx.lines[ctx.index] ?? '';
  if (isComment(line) || ctx.prose?.has(ctx.index)) return null;
  if (!rule.pattern.test(line)) return null;

  // Before any window work: a rule whose file-level precondition fails does not
  // apply to this file at all.
  if (rule.fileRequires && !rule.fileRequires.test(fileTextOf(ctx.lines))) return null;

  const back = rule.guardBack ?? 8;
  const forward = rule.guardForward ?? 0;
  const context = windowText(ctx.lines, ctx.index, back, forward, ctx.prose);

  if (rule.requires && !rule.requires.test(context)) return null;

  if (rule.lineGuard?.test(line)) return null;

  if (rule.enclosingCallGuard) {
    const callees = enclosingCallees(ctx.lines, ctx.index, back);
    if (callees.some((callee) => rule.enclosingCallGuard!.test(callee))) return null;
  }

  if (rule.constantInterpolationGuard && interpolationsAreConstant(line, fileTextOf(ctx.lines))) {
    return null;
  }

  if (rule.sanitizedHtmlGuard && hasSanitizedHtmlValue(line, fileTextOf(ctx.lines))) {
    return null;
  }

  if (rule.safeRedirectGuard && hasSafeRedirectValue(line, fileTextOf(ctx.lines))) {
    return null;
  }

  if (rule.filledBeforeUseGuard && bufferFilledBeforeUse(ctx)) return null;

  const guard = rule.guard === undefined ? GENERIC_GUARD : rule.guard;
  if (guard && (guard.test(line) || guard.test(context))) return null;

  const untrusted = untrustedPatternFor(ctx.language);
  const probeLine = ctx.language === 'shell' ? withoutSingleQuoted(line) : line;
  const probeContext = ctx.language === 'shell' ? withoutSingleQuoted(context) : context;
  const contextual = untrusted.test(probeLine) || untrusted.test(probeContext);
  if (rule.needsContext && !contextual) return null;

  // `inherent` short-circuits the whole context question. See the field's
  // documentation: for these rules the construct is the defect, so nearby
  // input cannot make it worse and its absence cannot make it better.
  const confidence: Confidence = rule.inherent
    ? 'evidence'
    : contextual
      ? 'contextual'
      : 'pattern';
  return { rule, confidence, severity: severityFor(rule.severity, confidence) };
}
