/**
 * Node.js-specific vulnerability rules.
 *
 * Why this file exists
 * --------------------
 * `code-rules.ts` is deliberately cross-language: SQL injection, path
 * traversal and weak hashing look much the same in six languages, so one rule
 * covers all of them. That breadth is also its limit. A whole set of classes
 * only exist inside the Node ecosystem — `vm2` sandbox escapes, Electron's
 * renderer settings, `node-serialize`'s function-executing deserialiser, JWT's
 * `none` algorithm, headless-browser navigation — and each one needs to know
 * which package it is looking at before it can say anything useful.
 *
 * Those live here, evaluated by the same engine and obeying the same
 * confidence model. Splitting them out keeps the cross-language table readable
 * and gives the ecosystem-specific rules one place to document their
 * preconditions.
 *
 * Provenance and licence
 * ----------------------
 * The *list of classes* covered here was drawn up by reading what njsscan
 * (github.com/ajinabraham/njsscan) reports on, to close a coverage gap against
 * an established Node scanner. Nothing was copied. njsscan is LGPL-3.0 and
 * this package is MIT, so its rule definitions could not be reused even in
 * translation; a set of vulnerability class names is a fact about the
 * ecosystem, not an expression of it. Every pattern, guard, title and
 * consequence below was written from scratch against this engine's semantics,
 * which are not njsscan's — it delegates to semgrep for AST matching, while
 * these are line-oriented regexes with guard windows and a severity cap.
 *
 * That difference shapes the rules. Where njsscan can write "this call, inside
 * a file that imported this module, not wrapped in an escaper", the closest
 * honest equivalent here is `fileRequires` for the import plus a narrow
 * pattern. Classes that genuinely need AST scope — entity-expansion limits,
 * taint through a router — are absent rather than approximated. See KNOWN_GAPS
 * at the foot of this file.
 */

import type { CodeRule } from './code-rules';

/**
 * A path is being assembled with containment already checked.
 *
 * Zip-slip is the one class in this file where the safe and unsafe forms are
 * the *same call* — `join(dest, entry.fileName)` — distinguished only by
 * whether the result is verified to stay under `dest`. So the guard has to
 * recognise containment checks specifically, which the generic guard does not:
 * a bare `startsWith` is too weak a signal to exonerate arbitrary rules, but
 * next to a path join it is exactly the check that matters.
 */
const PATH_CONTAINMENT_GUARD =
  /\bstartsWith\s*\(|\brelative\s*\(|\bnormalize\s*\(|\brealpath\b|\bisInside\b|\bwithin\s*\(|\bsanitiz\w*\b/i;

/** Packages whose archive entries carry an attacker-chosen path. */
const ARCHIVE_LIBRARY =
  /\b(?:adm-zip|unzipper|yauzl|node-stream-zip|extract-zip|decompress|tar-stream|tar-fs)\b|require\s*\(\s*['"]tar['"]|from\s+['"]tar['"]/;

/** Packages that drive a real browser, where a URL becomes a request from the server. */
const HEADLESS_BROWSER =
  /\b(?:puppeteer|playwright|phantom|phantomjs|wkhtmltopdf|wkhtmltoimage|chrome-aws-lambda|html-pdf)\b/;

/**
 * Evidence that a reflected origin was checked before being echoed.
 *
 * This rule cannot use the generic guard, and the reason is worth recording.
 * `Access-Control-Allow-Origin` contains the word "Allow"; the generic guard's
 * allow-list heuristic is case-insensitive and accepts a following `-`, so the
 * *header name itself* matched it. The rule was silently unable to ever fire —
 * it did not report fewer findings, it reported none, and only a failing test
 * distinguished that from "no vulnerable code here".
 *
 * What genuinely exonerates a reflected origin is a membership test on the
 * value, which is also the shape of the one correct implementation.
 */
const ORIGIN_ALLOWLIST_GUARD = /\b(?:includes|indexOf|has|test|find|some)\s*\(/;

/** Deserialisers that reconstruct functions, not just data. */
const FUNCTION_DESERIALIZER = /\b(?:node-serialize|serialize-to-js|funcster|cryo)\b/;

/**
 * A string literal being concatenated onto — either quote style, separately.
 *
 * One character class cannot do this. The interesting strings are the ones
 * containing the *other* quote:
 *
 *     "this.name === '" + name + "'"
 *     "//user[@id='" + id + "']"
 *
 * A combined `['"][^'"]*['"]` class stops dead at that inner quote and matches
 * nothing, which silently drops the most common injection shape. `code-rules.ts`
 * hit this with SQL and split the class per quote character; the same split is
 * needed everywhere a rule looks for assembled strings, so it lives here once.
 */
const CONCATENATED_STRING = String.raw`(?:"[^"\n]*"|'[^'\n]*')\s*\+`;

// A template literal with at least one interpolation. Written as a quoted
// string rather than with `String.raw`, because the pattern has to contain a
// backtick and a raw template literal cannot hold one unescaped.
const INTERPOLATED_TEMPLATE = '`[^`\\n]*\\$\\{';

export const NODE_RULES: readonly CodeRule[] = [
  // ── Code execution ───────────────────────────────────────────────────────
  {
    id: 'js-vm-untrusted-execution',
    title: 'script compiled and run by the `vm` module',
    consequence:
      'Node’s `vm` is not a security boundary — it isolates globals, not the process. Code reaching it can walk back out through any object it is handed and runs with the server’s full privileges.',
    cwe: 'CWE-94',
    severity: 'critical',
    languages: ['javascript', 'typescript'],
    pattern:
      /\bvm\s*\.\s*(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|\bnew\s+vm\s*\.\s*Script\s*\(/,
    // A `vm` call whose source is a build-time constant is a plugin loader, not
    // a vulnerability. The class only becomes real once the script text can be
    // influenced, so require that evidence before reporting at full severity.
    needsContext: true,
  },
  {
    id: 'js-vm2-sandbox',
    title: '`vm2` used as a sandbox',
    consequence:
      'vm2 was discontinued after a series of escapes that its maintainer judged unfixable by design. Any code it runs should be assumed to run on the host.',
    cwe: 'CWE-1104',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern: /\bnew\s+(?:NodeVM|VMScript)\s*\(|\bfrom\s+['"]vm2['"]|require\s*\(\s*['"]vm2['"]\s*\)/,
    // Nothing on the surrounding lines changes the answer: the package itself
    // is the finding, the same way a broken cipher is.
    inherent: true,
  },
  {
    id: 'js-function-deserialization',
    title: 'deserialiser that reconstructs functions',
    consequence:
      'These formats encode functions alongside data and invoke them on load, so parsing an attacker’s payload is executing it. No amount of validation after the parse call helps — the code has already run.',
    cwe: 'CWE-502',
    severity: 'critical',
    languages: ['javascript', 'typescript'],
    pattern: /\b(?:unserialize|deepDeserialize|deserialize)\s*\(/,
    // Without this the rule fires on every project that happens to own a
    // function called `deserialize`, which is most of them. The import is what
    // makes the call the dangerous one.
    fileRequires: FUNCTION_DESERIALIZER,
    // The parse *is* the execution, so nearby input cannot make it worse and
    // its absence cannot make it safe. Nobody round-trips a constant through
    // these libraries.
    inherent: true,
  },
  {
    id: 'js-template-injection',
    title: 'template compiled from a non-constant source',
    consequence:
      'Template languages are programming languages. A user-supplied template body is remote code execution, not cross-site scripting — the expression runs on the server before any output is escaped.',
    cwe: 'CWE-1336',
    severity: 'critical',
    languages: ['javascript', 'typescript'],
    pattern:
      /\b(?:handlebars|Handlebars|hbs|ejs|pug|jade|nunjucks|eta|twig|dot|doT|liquid|mustache)\s*\.\s*(?:compile|compileFile|render|renderString)\s*\(\s*(?:`[^`\n]*\$\{|[a-zA-Z_$][\w$.]*\s*[,)]|[a-zA-Z_$][\w$.]*\s*\+)/,
    // Rendering a template held in a variable is the normal case — it was read
    // from a file at boot. Only the version where request data reaches the
    // template *body* is this class.
    needsContext: true,
  },
  {
    id: 'js-shelljs-command-execution',
    title: 'shelljs command assembled from a string',
    consequence:
      '`shell.exec` runs its argument through a shell, so a `;` or backtick in an interpolated value runs as the server user.',
    cwe: 'CWE-78',
    severity: 'critical',
    languages: ['javascript', 'typescript'],
    pattern: new RegExp(
      `\\b(?:shell|shelljs|sh)\\s*\\.\\s*exec\\s*\\(\\s*(?:${INTERPOLATED_TEMPLATE}|${CONCATENATED_STRING}|[a-zA-Z_$][\\w$]*\\s*\\+)`,
    ),
    fileRequires: /\bshelljs\b/,
  },

  // ── Injection ────────────────────────────────────────────────────────────
  {
    id: 'js-nosql-where-expression',
    title: 'MongoDB `$where` built by string assembly',
    consequence:
      '`$where` is evaluated as JavaScript by the database server, once per document. An interpolated value can rewrite the predicate to `true` or run a denial-of-service loop inside the database.',
    cwe: 'CWE-943',
    severity: 'critical',
    languages: ['javascript', 'typescript'],
    pattern: new RegExp(
      `\\$where\\s*['"]?\\s*:\\s*(?:${INTERPOLATED_TEMPLATE}|${CONCATENATED_STRING})` +
        `|\\.\\s*\\$where\\s*=\\s*(?:${INTERPOLATED_TEMPLATE}|${CONCATENATED_STRING})`,
    ),
  },
  {
    id: 'js-xpath-injection',
    title: 'XPath expression built by concatenation',
    consequence:
      'A quote in the interpolated value closes the predicate early, so the query selects nodes the caller was never meant to read — the XML equivalent of `OR 1=1`.',
    cwe: 'CWE-643',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    // An XPath expression is recognisable by its own syntax — a descendant
    // axis or an attribute predicate. Matching on the *call* name alone would
    // flag every `select(` in the ecosystem. The quoted forms are split per
    // quote character for the reason given at CONCATENATED_STRING: the
    // predicate that makes it XPath usually contains the other quote.
    pattern: new RegExp(
      '\\b(?:xpath|xpathSelect|select|selectNodes|selectSingleNode|evaluate|find)\\s*\\(\\s*(?:' +
        '`[^`\\n]*(?:\\/\\/|\\[@)[^`\\n]*\\$\\{' +
        '|"[^"\\n]*(?:\\/\\/|\\[@)[^"\\n]*"\\s*\\+' +
        "|'[^'\\n]*(?:\\/\\/|\\[@)[^'\\n]*'\\s*\\+" +
        ')',
    ),
    fileRequires: /\bxpath\b|\bxmldom\b|\blibxmljs\b|\bxpath\.js\b/,
  },
  {
    id: 'js-regex-from-input',
    title: 'regular expression compiled from a variable',
    consequence:
      'A caller who controls the pattern controls the matcher: they can supply catastrophic backtracking to hang the event loop, or a permissive pattern that defeats whatever the regex was validating.',
    cwe: 'CWE-1333',
    severity: 'medium',
    languages: ['javascript', 'typescript'],
    pattern: new RegExp(
      `\\bnew\\s+RegExp\\s*\\(\\s*(?:${INTERPOLATED_TEMPLATE}|${CONCATENATED_STRING}|(?!['"\`/])[a-zA-Z_$][\\w$.]*\\s*[,)])`,
    ),
    needsContext: true,
  },

  // ── XML ──────────────────────────────────────────────────────────────────
  {
    id: 'js-xml-external-entities',
    title: 'XML parser configured to resolve entities',
    consequence:
      'An entity declaration in the document body makes the parser fetch a local file or an internal URL and paste the result into the parsed output — file disclosure and server-side request forgery from a document upload.',
    cwe: 'CWE-611',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    // The option name is the finding. Every parser in the ecosystem defaults
    // these off, so an explicit `true` is a deliberate re-enable.
    pattern: /\b(?:noent|resolveEntities|expandEntities|externalEntities|resolveExternals)\s*:\s*(?:true|1)\b/,
    inherent: true,
  },

  // ── Authentication and tokens ────────────────────────────────────────────
  {
    id: 'js-jwt-none-algorithm',
    title: 'JWT algorithm set to `none`',
    consequence:
      'The `none` algorithm means the signature is not checked. Anyone can mint a token with any claims — including another user’s id or an admin role — by base64-encoding a header and a body.',
    cwe: 'CWE-347',
    severity: 'critical',
    languages: ['javascript', 'typescript'],
    pattern: /\balgorithms?\s*:\s*\[?\s*['"]none['"]/i,
    inherent: true,
  },

  // ── Cryptography ─────────────────────────────────────────────────────────
  {
    id: 'js-broken-cipher-algorithm',
    title: 'broken cipher selected',
    consequence:
      'DES, 3DES, RC2, RC4, Blowfish and IDEA are all breakable with commodity hardware or have practical plaintext-recovery attacks. Data encrypted with them should be treated as encoded, not encrypted.',
    cwe: 'CWE-327',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern:
      /\bcreate(?:Cipher|Decipher)(?:iv)?\s*\(\s*['"](?:des|des3|des-ede\w*|3des|rc2|rc4|bf|blowfish|cast5?|idea|seed)\b/i,
    inherent: true,
  },
  {
    id: 'js-ecb-mode-cipher',
    title: 'block cipher in ECB mode',
    consequence:
      'ECB encrypts every block independently, so identical plaintext blocks produce identical ciphertext. Structure in the data survives encryption and blocks can be reordered or replayed without detection.',
    cwe: 'CWE-327',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern: /\bcreate(?:Cipher|Decipher)(?:iv)?\s*\(\s*['"][^'"\n]*-ecb\b/i,
    inherent: true,
  },
  {
    id: 'js-legacy-cipher-api',
    title: 'deprecated `createCipher` used',
    consequence:
      '`createCipher` derives the key from a passphrase with a single unsalted MD5 pass and uses a fixed all-zero IV, so the same passphrase always produces the same keystream. It was removed in Node 22.',
    cwe: 'CWE-327',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    // `createCipheriv` is the correct API and shares the prefix, so the
    // negative look-ahead is what separates the finding from the fix.
    pattern: /\bcrypto\s*\.\s*create(?:Cipher|Decipher)\s*\(/,
    lineGuard: /create(?:Cipher|Decipher)iv\s*\(/,
    inherent: true,
  },

  // ── Cross-site scripting ─────────────────────────────────────────────────
  {
    id: 'js-template-autoescape-disabled',
    title: 'template auto-escaping turned off',
    consequence:
      'Auto-escaping is the control that makes a template engine safe by default. Disabling it globally means every interpolation in every template becomes an injection point, including ones written later by someone who assumed the default.',
    cwe: 'CWE-79',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern: /\bautoescape\s*:\s*false\b|\bescape\s*:\s*false\b|\bnoEscape\s*:\s*true\b/,
    inherent: true,
  },
  {
    id: 'js-serialize-javascript-unsafe',
    title: '`serialize-javascript` in unsafe mode',
    consequence:
      'The `unsafe` flag turns off escaping of HTML-significant characters in the output. Embedding the result in a `<script>` block lets a string value close the tag and start a new one.',
    cwe: 'CWE-79',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern: /\bunsafe\s*:\s*true\b/,
    fileRequires: /\bserialize-javascript\b/,
    inherent: true,
  },
  {
    id: 'js-cors-origin-reflected',
    title: 'CORS origin reflected from the request',
    consequence:
      'Echoing the caller’s `Origin` header back as `Access-Control-Allow-Origin` allows every site, while looking like an allow-list. Combined with credentials, any page the victim visits can read their authenticated responses.',
    cwe: 'CWE-942',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    // Both spellings of the same mistake: writing the header directly, and
    // handing the request's origin to a CORS middleware's `origin` option.
    //
    // An earlier draft also matched a bare variable — `setHeader('…', origin)`
    // — which is wrong. A variable holding a *validated* origin is exactly
    // what the correct implementation looks like, and the rule cannot tell the
    // two apart. Only the visible read from the request qualifies.
    pattern:
      /\bAccess-Control-Allow-Origin['"]\s*,\s*(?:req|request|ctx)\s*\.|\borigin\s*:\s*(?:req|request|ctx)\s*\./,
    // Reflecting the header is the defect whatever surrounds it; there is no
    // arrangement of nearby lines that makes an echoed origin safe — except a
    // membership test on the value, which is what the guard looks for.
    inherent: true,
    guard: ORIGIN_ALLOWLIST_GUARD,
    /**
     * Logging the origin is not reflecting it.
     *
     * `origin: request.headers.origin` is the CORS mistake *and* the ordinary
     * way to record who called — the two are character-for-character
     * identical, and only what encloses them differs. A response header goes
     * out to the browser; a log line goes to stdout, where it grants nobody
     * anything.
     */
    enclosingCallGuard: /(?:^|\.)(?:log|debug|info|warn|error|trace|verbose|fatal)$/,
  },

  // ── Server-side request forgery ──────────────────────────────────────────
  {
    id: 'js-headless-browser-navigation',
    title: 'headless browser sent to a non-constant URL',
    consequence:
      'The browser runs on the server, inside the private network. A controlled URL reaches the cloud metadata endpoint, localhost admin panels and internal services — and `file://` reads the disk.',
    cwe: 'CWE-918',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern:
      /\.\s*(?:goto|setContent|navigate)\s*\(\s*(?:`[^`\n]*\$\{|(?!['"`])[a-zA-Z_$][\w$.]*\s*[,)])/,
    fileRequires: HEADLESS_BROWSER,
    needsContext: true,
  },

  // ── Path handling ────────────────────────────────────────────────────────
  {
    id: 'js-archive-entry-path',
    title: 'archive entry written to a path built from its own name',
    consequence:
      'An entry named `../../etc/cron.d/x` escapes the extraction directory when its name is joined to the destination. Overwriting a file outside the target — a systemd unit, an SSH key, a deployed script — is code execution on the next run.',
    cwe: 'CWE-22',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern:
      /\b(?:join|resolve)\s*\(\s*[^,\n)]+,\s*[a-zA-Z_$][\w$]*\s*\.\s*(?:entryName|fileName|filename|name|path)\b/,
    fileRequires: ARCHIVE_LIBRARY,
    guard: PATH_CONTAINMENT_GUARD,
    // The containment check comes *after* the join — you build the path, then
    // verify it stayed inside. A backwards-only window would miss every
    // correct implementation and report the safe code alongside the unsafe.
    guardForward: 3,
  },

  // ── Electron ─────────────────────────────────────────────────────────────
  {
    id: 'js-electron-node-integration',
    title: 'Electron renderer given Node access',
    consequence:
      'With node integration on — or context isolation off — any script that reaches the page reaches `require`. A single XSS in rendered content becomes `child_process.exec` on the user’s machine.',
    cwe: 'CWE-1188',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern:
      /\bnodeIntegration(?:InWorker|InSubFrames)?\s*:\s*true\b|\bcontextIsolation\s*:\s*false\b|\benableRemoteModule\s*:\s*true\b|\bsandbox\s*:\s*false\b/,
    inherent: true,
  },
  {
    id: 'js-electron-web-security-disabled',
    title: 'Electron web security disabled',
    consequence:
      'Turning off `webSecurity` drops the same-origin policy for the window, so remote content can read local files and every other origin the app has loaded.',
    cwe: 'CWE-1173',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern: /\bwebSecurity\s*:\s*false\b|\ballowRunningInsecureContent\s*:\s*true\b|\bwebviewTag\s*:\s*true\b/,
    inherent: true,
  },
  {
    id: 'js-electron-open-external',
    title: 'Electron `openExternal` with a non-constant URL',
    consequence:
      '`shell.openExternal` hands the string to the operating system’s handler. A `file://` path executes a local binary and, on Windows, an SMB path executes a remote one.',
    cwe: 'CWE-749',
    severity: 'high',
    languages: ['javascript', 'typescript'],
    pattern: /\bshell\s*\.\s*openExternal\s*\(\s*(?:`[^`\n]*\$\{|(?!['"`])[a-zA-Z_$][\w$.]*\s*[,)])/,
    needsContext: true,
  },

  // ── Hardening and resource limits ────────────────────────────────────────
  {
    id: 'js-helmet-protection-disabled',
    title: 'security header explicitly disabled',
    consequence:
      'Each of these switches off a browser-side protection that was already on. The header stops being sent, so the defence it enables — framing, sniffing, referrer leakage, transport downgrade — is available to an attacker again.',
    cwe: 'CWE-693',
    severity: 'medium',
    languages: ['javascript', 'typescript'],
    pattern:
      /\b(?:contentSecurityPolicy|frameguard|hsts|noSniff|xssFilter|hidePoweredBy|referrerPolicy|dnsPrefetchControl|ieNoOpen|permittedCrossDomainPolicies|crossOriginEmbedderPolicy|crossOriginOpenerPolicy|crossOriginResourcePolicy|originAgentCluster)\s*:\s*false\b/,
    inherent: true,
  },
  {
    id: 'js-buffer-bounds-check-disabled',
    title: 'buffer bounds checking turned off',
    consequence:
      'With `noAssert` the read or write is not range-checked, so an offset past the end of the buffer returns adjacent heap memory or corrupts it instead of throwing.',
    cwe: 'CWE-125',
    severity: 'medium',
    languages: ['javascript', 'typescript'],
    // The trailing `true` on a Buffer numeric accessor *is* `noAssert` — it is
    // the last positional parameter of every one of these methods. Anchoring
    // on the accessor name is what keeps this from matching `, true)` on any
    // call in the codebase.
    pattern:
      /\b(?:read|write)(?:U?Int(?:8|16|32)(?:[BL]E)?|U?Int[BL]E|Float[BL]E|Double[BL]E)\s*\([^)\n]*,\s*true\s*\)|\bnoAssert\s*:\s*true\b/,
    inherent: true,
  },
  {
    id: 'js-uninitialized-buffer',
    title: 'buffer allocated without zeroing',
    consequence:
      '`allocUnsafe` and the old `new Buffer(size)` hand back whatever was previously in that heap memory — keys, session tokens, other users’ request bodies. Anything not overwritten before the buffer is sent leaks it.',
    cwe: 'CWE-908',
    severity: 'medium',
    languages: ['javascript', 'typescript'],
    pattern: /\bBuffer\s*\.\s*allocUnsafe(?:Slow)?\s*\(|\bnew\s+Buffer\s*\(\s*(?![`'"])[a-zA-Z_$0-9]/,
    inherent: true,
    // Filling the buffer yourself is the whole reason to call `allocUnsafe`,
    // so reporting every call reports correct code. What is left reported is
    // an allocation whose bytes are never written before it escapes.
    filledBeforeUseGuard: true,
  },
  {
    id: 'js-oversized-request-body-limit',
    title: 'request body limit raised to a very large value',
    consequence:
      'A body limit in the tens of megabytes lets a handful of concurrent requests exhaust memory, and the parse happens before any authentication check the route performs.',
    cwe: 'CWE-400',
    severity: 'medium',
    languages: ['javascript', 'typescript'],
    // Two or more digits before `mb` — 50mb and up. A limit is a *good* thing;
    // only an ineffective one is the finding.
    pattern: /\blimit\s*:\s*['"]\s*(?:[5-9]\d|\d{3,})\s*mb\s*['"]|\blimit\s*:\s*['"]\s*\d+\s*gb\s*['"]/i,
    inherent: true,
  },

  // ── Information disclosure ───────────────────────────────────────────────
  {
    id: 'js-error-detail-returned',
    title: 'error object or stack trace sent to the client',
    consequence:
      'A stack trace names absolute paths, package versions and internal function names, and framework errors often carry the failing query or connection string with them. It is a map of the server, handed out on request.',
    cwe: 'CWE-209',
    severity: 'medium',
    languages: ['javascript', 'typescript'],
    // `res.status(500).send(…)` is the overwhelmingly common spelling, so the
    // optional `.status(…)` hop is not a nicety — without it the rule misses
    // nearly every real occurrence.
    pattern:
      /\bres\s*\.\s*(?:status\s*\([^)\n]*\)\s*\.\s*)?(?:send|json|end|write)\s*\(\s*(?:[a-zA-Z_$][\w$]*\s*\.\s*stack\b|(?:error|err|e)\s*[,)])|\.\s*(?:send|json)\s*\(\s*\{[^}\n]*\b(?:stack|err|error)\s*:\s*(?:error|err|e)\s*[,}]/,
    inherent: true,
  },
];

/**
 * KNOWN_GAPS — Node classes deliberately not implemented here.
 *
 * Each of these needs analysis this engine does not do, and the regex that
 * would approximate it fires on ordinary code often enough to make the whole
 * rule set less useful. They are listed rather than silently omitted so the
 * next person does not have to rediscover why.
 *
 *   XML entity-expansion DoS (CWE-776)
 *     The defect is the *absence* of an expansion limit, which is a property
 *     of parser configuration spread across a file, not a line.
 *
 *   Missing anti-CSRF, rate limiting, security headers (CWE-352, CWE-770)
 *     Also absence-of-evidence, and genuinely whole-project. Handled instead
 *     by `controls.ts`, which accumulates across the walk and reports once —
 *     and only when asked, because a missing control is a weaker claim than a
 *     present defect.
 *
 *   JWT tokens not revocable, sensitive claims in the payload
 *     Requires knowing what a claim means. `{ ssn: user.ssn }` and
 *     `{ sub: user.id }` are the same shape.
 *
 *   Prototype-pollution gadget chains
 *     The direct assignment forms are covered by `js-prototype-pollution` in
 *     the cross-language table. Reaching a gadget through a merge helper needs
 *     interprocedural reasoning.
 *
 *   Sequelize / driver TLS options
 *     `rejectUnauthorized: false` is already reported by
 *     `tls-verification-disabled`, which is language-agnostic and catches it
 *     wherever it appears. A driver-specific duplicate would double-report.
 */
