/**
 * Credential-shape rules for `threatcrush scan`.
 *
 * These are the rules ThreatCrush already scored 0.0% false positives on
 * against the public testbed's control group, so the bar for changing one is
 * high: a secret rule earns its place by matching material that is a
 * credential, not by matching material that looks vaguely random.
 *
 * The distinction that keeps the false-positive rate at zero is *shape with a
 * vendor prefix*. `AKIA…`, `ghp_…`, `xoxb-…`, `sk_live_…` are issued formats —
 * nothing else produces them. Entropy alone is not a rule here, because
 * entropy alone flags every UUID, hash and minified bundle in the tree.
 *
 * Two lines in the testbed corpus are the reason for that discipline. Both
 * live in the same `.env` file as five real credentials:
 *
 *     AWS_ROLE_ARN=arn:aws:iam::123456789012:role/app-runtime
 *     DATABASE_URL_SSM_PARAMETER=/prod/app/database-url
 *
 * An identifier and a lookup path. Both sit under secret-shaped variable
 * names, and neither is a credential. A rule keyed on the variable name would
 * flag both.
 */

import type { Severity } from './types';

export interface SecretRule {
  id: string;
  /** Vendor-facing name, e.g. "AWS Access Key". */
  name: string;
  pattern: RegExp;
  severity: Severity;
  cwe: string;
  /** What an attacker does with it. */
  consequence: string;
  /**
   * Does this rule key on a *keyword* rather than on an issued format?
   *
   * `AKIA…` and `ghp_…` are minted by a vendor: nobody types one by accident,
   * so a match is a credential wherever it appears — including in a test, where
   * it is reported at `low` but still reported. The keyword-shaped rules are
   * the opposite. `password = '…'` fires on the *variable name*, and the value
   * beside it in a test file is a fixture in overwhelming proportion.
   *
   * Only rules marked here are eligible for the test-fixture exemption in
   * `isTestFixtureValue`. The distinction is the whole reason that exemption is
   * safe: it can never silence a vendor-issued key.
   */
  keywordShaped?: boolean;
}

export const SECRET_RULES: readonly SecretRule[] = [
  {
    id: 'secret-aws-access-key',
    name: 'AWS Access Key',
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence: 'Paired with a secret key, grants the API access of whatever IAM principal issued it.',
  },
  {
    id: 'secret-aws-secret-key',
    name: 'AWS Secret Access Key',
    pattern:
      /(?:aws_secret_access_key|AWS_SECRET(?:_ACCESS_KEY)?)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence: 'The other half of an AWS credential pair; on its own it is still the hard half to guess.',
  },
  {
    id: 'secret-github-token',
    name: 'GitHub Token',
    pattern: /\b(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b/,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence: 'Repository read or write as the issuing account, including the ability to push workflow changes.',
  },
  {
    id: 'secret-npm-token',
    name: 'npm Token',
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence: 'Publish rights to every package the account owns — a supply-chain compromise in one command.',
  },
  {
    id: 'secret-private-key',
    name: 'Private Key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence: 'Key material, committed. Rotation is the only remediation.',
  },
  {
    id: 'secret-slack-token',
    name: 'Slack Token',
    pattern: /\bxox[bpoasr]-[A-Za-z0-9-]{10,}/,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence: 'Read and post access to the workspace as the installing app.',
  },
  {
    id: 'secret-slack-webhook',
    name: 'Slack Webhook URL',
    pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_+\/-]{6,}/,
    severity: 'high',
    cwe: 'CWE-798',
    consequence: 'The URL *is* the credential — anyone holding it can post to that channel.',
  },
  {
    id: 'secret-stripe-key',
    name: 'Stripe Key',
    pattern: /\b(?:sk_live_|rk_live_|sk_test_|rk_test_)[A-Za-z0-9]{20,}\b/,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence: 'Charge, refund and customer-data access against the account.',
  },
  {
    id: 'secret-sendgrid-key',
    name: 'SendGrid API Key',
    pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence: 'Send mail as the domain — the credential behind most convincing phishing from a real sender.',
  },
  {
    id: 'secret-google-api-key',
    name: 'Google API Key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
    severity: 'high',
    cwe: 'CWE-798',
    consequence: 'Quota theft at minimum; API access to whatever the key was scoped to at worst.',
  },
  {
    id: 'secret-openai-key',
    name: 'OpenAI API Key',
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence: 'Billed inference against the owner’s account, with no per-key spend limit by default.',
  },
  {
    id: 'secret-anthropic-key',
    name: 'Anthropic API Key',
    pattern: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{32,}\b/,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence: 'Billed inference against the owner’s account.',
  },
  {
    id: 'secret-database-url',
    name: 'Database URL with credentials',
    // Requires a credential segment before the `@` — `postgres://localhost/db`
    // is a hostname, not a secret.
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|clickhouse):\/\/[^\s'"@\/]*:[^\s'"@\/]*@[^\s'"]+/i,
    severity: 'high',
    cwe: 'CWE-798',
    consequence: 'Direct database access, usually bypassing every application-level authorisation check.',
  },
  {
    id: 'secret-jwt',
    name: 'JSON Web Token',
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_.+/=-]*/,
    severity: 'medium',
    cwe: 'CWE-798',
    consequence: 'Session or service identity until it expires — and committed tokens are usually long-lived.',
    keywordShaped: true,
  },
  {
    id: 'secret-generic-api-key',
    name: 'Generic API Key',
    // Quoted assignment only. An unquoted value in a `.env` is covered by the
    // vendor-prefixed rules above; matching it here is what starts flagging
    // ARNs and parameter-store paths.
    pattern: /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[=:]\s*['"]([A-Za-z0-9\-_.]{20,})['"]/i,
    severity: 'high',
    cwe: 'CWE-798',
    consequence: 'Whatever the third-party service lets the key do, for as long as it stays valid.',
    keywordShaped: true,
  },
  {
    id: 'secret-generic-credential',
    name: 'Hardcoded Credential',
    pattern: /(?:secret|password|passwd|pwd|token)\s*[=:]\s*['"]([^'"\s]{8,})['"]/i,
    severity: 'high',
    cwe: 'CWE-798',
    consequence: 'A password in source is a password in every clone, fork and CI cache of that source.',
    keywordShaped: true,
  },
  {
    id: 'secret-hex-token',
    name: 'High-entropy Hex Token',
    pattern: /(?:token|key|secret|auth|signing)\w*\s*[=:]\s*['"]?([0-9a-f]{32,})['"]?/i,
    severity: 'medium',
    cwe: 'CWE-798',
    consequence: 'Signing secrets and session keys are usually hex; a leaked one forges anything they sign.',
    keywordShaped: true,
  },
];

/**
 * Values that satisfy a credential shape but are not credentials.
 *
 * Kept deliberately short. Every entry is a documented, publicly-published
 * placeholder — not a guess that something "looks like a test value". A
 * generous allow-list here is how a scanner talks itself out of a real finding.
 */
const KNOWN_PLACEHOLDERS = [
  // Deliberately NOT here: AWS's published documentation key/secret pair
  // (`AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/…`). GitHub allow-lists them, and
  // the argument for following suit is that they authenticate nothing. The
  // argument against is stronger: they appear in a repository because someone
  // pasted a credentials template and left it there, and the remediation —
  // move this to the secret manager — is identical to the one for a live key.
  // Exempting them means the scanner goes quiet on the file most likely to
  // acquire a real key next.
  /\bEXAMPLE_?KEY\b/i,
  /\bYOUR_[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD)\b/,
  /\b(?:xxx+|X{4,}|\*{4,}|<[a-z-]+>)\b/,
  /\bchangeme\b/i,
  // The metasyntactic pair in a connection string, `postgres://user:pass@host`.
  // This is not the AWS case above and the distinction is the whole reason it
  // is allowed: `AKIAIOSFODNN7EXAMPLE` is a real credential *format* carrying a
  // fake value, so it arrives by way of a pasted template. `user:pass` is the
  // English words sitting where a credential goes, which is how every database
  // driver writes its DSN in its own README, and nobody pastes that out of a
  // secret manager.
  //
  // Both halves have to be metasyntactic. `root:hunter2@` is not exempt, since
  // a real password beside a common username is the case this must not swallow.
  /:\/\/(?:user(?:name)?|admin|root|dbuser|myuser):(?:pass(?:word|wd)?|secret|dbpass|mypassword)@/i,
];

/**
 * Whether the matched text is a documented placeholder rather than material.
 *
 * Note what this does *not* do: it does not exempt a value for being all
 * zeros, all A's, or otherwise "obviously fake". Those shapes are exactly what
 * the testbed's fixtures use, deliberately, and a scanner that skips them
 * scores zero on a corpus of real credential formats. Only values a vendor has
 * published as examples are exempt.
 */
export function isKnownPlaceholder(text: string): boolean {
  return KNOWN_PLACEHOLDERS.some((pattern) => pattern.test(text));
}

/*
 * Deliberately absent: a rule exempting a *typed sequence*.
 *
 * `ASIA1A2B3C4D5E6F7890` is what mulgadc/spinifex's API documentation is built
 * from — digits running 1234567890, letters running ABCDEF, a person walking
 * two keyboards at once. Six of them sit in `docs/`, and because a documented
 * key is neither a fixture nor annotated nor self-describing, those six are
 * every remaining critical on that repository. Detecting the two monotonic runs
 * is easy, and it was written, measured and removed again.
 *
 * It cannot be had. `false-positives.test.ts` pins `AKIA1234567890ABCDEF` as a
 * key that must never be exempted however it is named, and that value *is* a
 * typed sequence — the same shape, indistinguishable by any rule that is not
 * simply a list of the two literals. The header above says why the test is
 * right: the corpus this scanner is measured against builds its fixtures out of
 * exactly these shapes, so a scanner that skips them scores zero on a corpus of
 * real credential formats. Quiet documentation is not worth that trade.
 *
 * The noise is real and stays. It is a cost of keying on value rather than on
 * path, which remains the correct axis — see `isDocPath`.
 */

/**
 * Is the value the example text an empty input field shows?
 *
 * `placeholder` is the one HTML attribute whose contents are, by definition,
 * not data — it is the grey hint that disappears the moment a user types. A
 * credential-shaped string there is the interface telling somebody what to
 * paste, which is the same reason spinifex's cert-import dialog holds
 * `placeholder="-----BEGIN PRIVATE KEY-----"`: a banner with no key under it.
 *
 * Both of those were criticals, and a critical is what a maintainer reads
 * first. Softened rather than skipped, like everything else here — a real key
 * left in a placeholder is rendered to every visitor, so it stays in the report.
 */
export function isPlaceholderAttribute(line: string, value: string): boolean {
  const at = line.lastIndexOf(value);
  if (at === -1) return false;
  return /(?:^|\s)(?:aria-)?placeholder\s*=\s*[{("'`]*$/i.test(line.slice(0, at));
}

/**
 * Is the matched value a variable reference rather than a literal?
 *
 * The highest-volume false positive outside test files, and the one that needs
 * no judgement to dismiss: a value made entirely of an expansion holds nothing.
 *
 *     SUPABASE_ACCESS_TOKEN="${SUPABASE_ACCESS_TOKEN:-}"
 *     TWILIO_AUTH_TOKEN="${TWILIO_AUTH_TOKEN:-}"
 *
 * Those two lines are the canonical shape of a script that *refuses* to default
 * a secret — the `:-` with an empty right-hand side exists precisely so the
 * script fails when the variable is unset. Reporting them as hardcoded
 * credentials flags the remediation as the defect.
 *
 * The one thing this must not swallow is an expansion with a real fallback.
 * `${DB_PASSWORD:-hunter2}` *is* a hardcoded credential — it is the default the
 * process runs with — so a literal on the right of `:-` disqualifies the value.
 * A fallback that is itself another variable carries no literal and stays
 * exempt.
 */
export function isVariableReference(value: string): boolean {
  const trimmed = value.trim();

  // `${NAME}`, `${NAME:-}`, `${NAME:-$OTHER}` — shell parameter expansion, and
  // the same syntax a JavaScript template literal uses.
  const braced = /^\$\{\s*([A-Za-z_][\w.]*)\s*(?::?[-=+?]([\s\S]*))?\}$/.exec(trimmed);
  if (braced) {
    const fallback = braced[2];
    if (fallback === undefined || fallback.trim() === '') return true;
    return /^\$\{?[A-Za-z_][\w.]*\}?$/.test(fallback.trim());
  }

  return (
    /^\$[A-Za-z_]\w*$/.test(trimmed) || // $VAR
    /^\$\([\s\S]*\)$/.test(trimmed) || // $(command substitution)
    /^%[A-Za-z_]\w*%$/.test(trimmed) || // %VAR% on Windows
    /^\{\{[\s\S]*\}\}$/.test(trimmed) || // {{ template }}
    /^#\{[\s\S]*\}$/.test(trimmed) || // #{ruby}
    /^<%=?[\s\S]*%>$/.test(trimmed) // <%= erb %>
  );
}

/** Stems that announce a value as scaffolding rather than material. */
const FIXTURE_STEMS = [
  'test', 'mock', 'fake', 'dummy', 'stub', 'sample', 'example', 'placeholder',
  'fixture', 'invalid', 'expired', 'forged', 'bogus', 'notreal', 'nonexistent',
  'changeme', 'foobar', 'lorem',
];

/**
 * Words that appear in every declaration and say nothing about the value.
 *
 * Without this, `const` in the key and any value containing the letters
 * "const" would agree, and more usefully: a keyword shared by all declarations
 * is not evidence that the value echoes the *name*.
 */
const KEY_NOISE = new Set(['const', 'this', 'return', 'await', 'async', 'expect', 'value']);

/** Alphabetic runs, splitting snake_case, kebab-case and camelCase alike. */
function words(text: string): string[] {
  return text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[^A-Za-z]+/g, ' ')
    .toLowerCase()
    .split(' ')
    .filter(Boolean);
}

/**
 * In a test file, does this value describe itself as a fixture?
 *
 * Applied only to `keywordShaped` rules and only under `isTestPath`, which is
 * what keeps it from being the generous allow-list the header warns about. Two
 * signals, both read off the value rather than off the variable holding it:
 *
 *   1. A word of it begins with a fixture stem — `test-token`,
 *      `mock-session-token`, `testpassword123`, `forgedToken`. Matching a stem
 *      at the start of a *word* rather than anywhere in the string is what
 *      keeps `latest` and `contest` from reading as "test".
 *   2. It repeats a word from its own key — `access_token: 'access-token'`,
 *      `const password = 'mySecurePassword123'`, `testGPGPassword:
 *      'gpgPassword456'`. A credential that spells out the word "password" is
 *      a description of one, not one.
 *
 * The second signal is capped at 48 characters, and that cap is load-bearing.
 * Base64 is dense enough that a long blob contains a four-letter word by
 * accident — a 200-character service JWT would eventually "echo" any key you
 * put beside it and exempt itself. Real credentials are long and fixtures are
 * short, so the cap costs nothing and closes the hole.
 *
 * What stays reported, deliberately: a value with neither signal. In the
 * corpus this was written against that left four findings out of seventy-nine,
 * one of them a real Supabase service JWT pasted into a debug script — which
 * is exactly the one worth a human's attention.
 */
export function isTestFixtureValue(line: string, value: string): boolean {
  const valueWords = words(value);
  if (valueWords.some((word) => FIXTURE_STEMS.some((stem) => word.startsWith(stem)))) return true;

  return describesItsOwnKey(line, value);
}

/**
 * Does the value repeat a word from the name of the thing holding it?
 *
 * Signal 2 of `isTestFixtureValue`, lifted out because the reasoning behind it
 * was never about tests. `access_token: 'access-token'` is a description of a
 * credential rather than a credential in a test file and in production code
 * alike — the difference is only what to do about it, and that is the caller's
 * decision, not this function's.
 *
 * Outside a test the caller downgrades instead of skipping, which is what makes
 * generalising it safe. `DB_PASSWORD = "password123"` echoes its key and is
 * also a real, terrible, hardcoded credential; it stays in the report.
 *
 * This is the third of the three structural false-positive causes measured on
 * Go repositories, and on a cloud project it is the loudest. An AWS-compatible
 * API surface is built out of constants that name credentials without being
 * them:
 *
 *     ErrExpiredToken         = "ExpiredToken"           // an API error code
 *     pathToken               = "/latest/api/token"      // a URL path
 *     hdrToken                = "X-aws-ec2-metadata-token"  // a header name
 *     CommandSetMasterPassword = "set-master-password"   // a CLI verb
 *
 * Every one matches `secret-generic-credential`, which keys on the *word*
 * `token` or `password` next to a quoted string and never looks at what the
 * string is. Every one repeats its own key.
 *
 * The 48-character cap is load-bearing and is explained on `isTestFixtureValue`:
 * base64 is dense enough that a long blob eventually contains a four-letter
 * word by accident and would exempt itself.
 */
export function describesItsOwnKey(line: string, value: string): boolean {
  if (value.length > 48) return false;

  const valueAt = line.lastIndexOf(value);
  const key = valueAt === -1 ? line : line.slice(0, valueAt);
  const flattened = words(value).join('');

  return words(key)
    .filter((word) => word.length >= 4 && !KEY_NOISE.has(word))
    .some((word) => flattened.includes(word));
}

/**
 * Replace anything that looks like credential material with asterisks.
 *
 * Applied to every excerpt on a secret finding before it reaches a terminal, a
 * SARIF file, a CI log or a PR comment. A scanner that prints the secret it
 * found has moved the secret somewhere new, and CI logs are retained and, on
 * public forks, published.
 */
export function redactSecret(line: string): string {
  return line.replace(/([A-Za-z0-9+/=_.-]{12,})/g, (match) => {
    if (match.length <= 12) return match;
    return `${match.slice(0, 3)}${'*'.repeat(Math.min(16, match.length - 3))}`;
  });
}

/** Files whose mere presence is worth reporting, independent of content. */
export const SENSITIVE_FILES: readonly { pattern: string; message: string; severity: Severity }[] = [
  { pattern: '.env', message: 'Environment file committed — the usual home of every runtime credential', severity: 'high' },
  { pattern: '.env.local', message: 'Local environment file committed', severity: 'high' },
  { pattern: '.env.production', message: 'Production environment file committed', severity: 'critical' },
  { pattern: 'id_rsa', message: 'Private SSH key committed', severity: 'critical' },
  { pattern: 'id_ed25519', message: 'Private SSH key committed', severity: 'critical' },
  { pattern: 'id_ecdsa', message: 'Private SSH key committed', severity: 'critical' },
  { pattern: '.pem', message: 'PEM certificate or key file committed', severity: 'high' },
  { pattern: '.p12', message: 'PKCS#12 keystore committed', severity: 'high' },
  { pattern: '.pfx', message: 'PKCS#12 keystore committed', severity: 'high' },
  { pattern: '.keystore', message: 'Java keystore committed', severity: 'high' },
  // Deliberately not `.npmrc`. Its presence is normal; only an `_authToken`
  // line in it is a credential, and that is a content match, not a filename
  // match. Reporting the file itself trades a real finding for a chore.
];
