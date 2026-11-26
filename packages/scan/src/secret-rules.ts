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

import { attackVector } from './references';
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
  /**
   * A second look at the lines around a match, for rules whose pattern is only
   * the *label* of a credential rather than the credential itself. Returning
   * false drops the match: it is not key material. See `hasPemBody`.
   */
  confirm?: (lines: readonly string[], index: number, match: RegExpExecArray) => boolean;
  /**
   * Rule ids this one replaces when both match the same line. A GitHub App key
   * is also a private key, and one finding that says which is better than two
   * that say the same thing at different levels of detail.
   */
  supersedes?: readonly string[];
  /**
   * Drop this match when any vendor-format (non-`keywordShaped`) rule matched
   * the same line. `GITHUB_TOKEN=ghp_…` is a GitHub token; the generic
   * high-entropy rule has nothing to add to that.
   */
  yieldsToVendorRules?: boolean;
  /** How to fix it, in a sentence. */
  fix?: string;
  /** Write-up of the attack this credential enables. See `references.ts`. */
  reference?: string;
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
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence: 'Key material, committed. Rotation is the only remediation.',
    confirm: (lines, index, match) => hasPemBody(lines, index, match),
    fix: 'Regenerate the key at its issuer, delete the old one there, and load the new one from a secret manager. Deleting the file does not help: it is in the history.',
    reference: attackVector('unrotated-github-app-keys'),
  },
  {
    id: 'secret-github-app-private-key',
    name: 'GitHub App Private Key',
    // The same banner, confirmed by an App id in the same file. That pairing is
    // everything needed to mint installation tokens for every org the App is
    // installed in, which is why it outranks a bare private key.
    pattern: /-----BEGIN (?:RSA |ENCRYPTED )?PRIVATE KEY-----/,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence:
      'With the App id beside it, anyone holding this file mints installation tokens for every account the App is installed on and pushes, merges or reads as `<app>[bot]`. Suspending the App does not stop it: the key can unsuspend.',
    confirm: (lines, index, match) => hasPemBody(lines, index, match) && hasGithubAppId(lines),
    supersedes: ['secret-private-key'],
    fix: 'Generate a new private key in the App settings, delete every old key there, then delete or rotate the installations that matter. Treat every copy on disk (and its `.bak`) as burned.',
    reference: attackVector('unrotated-github-app-keys'),
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
    id: 'secret-resend-key',
    name: 'Resend API Key',
    // Resend issues `re_` + 8 base58 + `_` + 24 base58 (the shape TruffleHog's
    // detector pins). The pattern is wider than that on purpose: a key that has
    // been re-cut, truncated in a paste or issued under an older layout still
    // starts `re_` and is still a key, and the narrow form let one through in a
    // committed `.env` backup. Wide alone would flag `re_compile_pattern_cache`,
    // so `looksLikeResendKey` asks for the issued shape or for key material.
    pattern: /\bre_[A-Za-z0-9_]{20,}\b/,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence: 'Send mail as every verified domain on the account.',
    confirm: (_lines, _index, match) => looksLikeResendKey(match[0]),
    fix: 'Revoke the key in the Resend dashboard, issue a new one scoped to sending, and load it from a secret manager.',
  },
  {
    id: 'secret-supabase-service-role',
    name: 'Supabase service-role key',
    // A JWT whose payload claims `role: service_role`. Decoded rather than
    // guessed from the variable name: the anon key has the same shape and is
    // public by design.
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}/,
    severity: 'critical',
    cwe: 'CWE-798',
    consequence: 'Bypasses every row-level security policy: full read and write on the project database.',
    confirm: (_lines, _index, match) => jwtClaimsRole(match[0], 'service_role'),
    supersedes: ['secret-jwt', 'secret-generic-high-entropy'],
    fix: 'Rotate the JWT secret (which reissues both keys) and keep the service-role key server-side only.',
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
    id: 'secret-generic-high-entropy',
    name: 'High-entropy secret in a *_SECRET / *_PRIVATE_KEY / *_TOKEN variable',
    // The unquoted `.env` assignment the quoted-only generic rules above leave
    // alone. Safe to key on the name only because the value must also look
    // like key material: long, mixed-class and high-entropy (see
    // `looksLikeKeyMaterial`). An ARN or a parameter-store path fails that,
    // which is what keeps the header's two counter-examples quiet. All-hex
    // values belong to `secret-hex-token` and are left to it.
    pattern:
      /^\s*(?:export\s+)?(?![A-Z0-9_]*(?:PUBLIC|ANON|PUBLISHABLE))[A-Z][A-Z0-9_]*(?:SECRET|PRIVATE_KEY|_TOKEN|_API_KEY|_PASSWORD|_PASSWD)[A-Z0-9_]*\s*[=:]\s*([A-Za-z0-9+/_.~-]{20,}={0,2})\s*$/,
    severity: 'high',
    cwe: 'CWE-798',
    consequence: 'Whatever the variable unlocks, in every clone, backup and image layer that carries this file.',
    keywordShaped: true,
    yieldsToVendorRules: true,
    confirm: (_lines, _index, match) => looksLikeKeyMaterial(match[1] ?? ''),
    supersedes: ['secret-jwt'],
    fix: 'Rotate the value, then load it from a secret manager or the deploy environment instead of a committed file.',
    reference: attackVector('unrotated-github-app-keys'),
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
/**
 * A template expression, in the syntaxes that reach a connection string: Go
 * and Handlebars `{{…}}`, shell and JavaScript `${…}`, bare `$VAR`, printf
 * `%s`/`%d`/`%v`, the single brace of a Python f-string or `str.format`
 * (`{pw}`), and the `<pw>` of a usage line in a comment or README. Anchored to
 * the end of the credential segment so it has to fill the slot rather than
 * merely appear somewhere near it.
 *
 * The single brace and the angle brackets are the two that a tool building
 * DSNs actually writes — `f"postgres://postgres:{pw}@{host}/{db}"` is the code
 * that assembles a connection string, not a credential sitting in a file. Note
 * the angle-bracket form cannot be left to the `<[a-z-]+>` entry in
 * KNOWN_PLACEHOLDERS below: that one is `\b`-anchored, and there is no word
 * boundary between the `:` of the DSN and the `<` that follows it.
 */
const INTERPOLATION = String.raw`(?:\{\{[^}]*\}\}|\$\{[^}]*\}|\$[A-Za-z_]\w*|%[sdv]|\{[^{}\s'"@/]+\}|<[A-Za-z_][\w.-]*>)`;

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
  // A DSN whose password slot is an interpolation the runtime substitutes:
  // `postgres://{{.user}}:{{.pass}}@{{.host}}/{{.name}}`. This is a stronger
  // claim than the metasyntactic pair above rather than a looser one — that
  // rule reads English words and infers intent, whereas `{{…}}`, `${…}` and
  // `%s` cannot appear in a credential at all, because the value that reaches
  // the driver is whatever the template engine puts there. A tool that builds
  // connection strings holds these by the hundred and none of them is a secret.
  //
  // Only the password slot decides it. The username is not a credential, so a
  // literal one beside a templated password leaks nothing, while the reverse —
  // `postgres://{{.user}}:hunter2@` — is a real password and stays reported.
  new RegExp(String.raw`://[^\s'"@/]*:${INTERPOLATION}@`),
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
 * mulgadc/spinifex's API documentation is built out of an `ASIA` prefix
 * followed by `1A2B3C4D5E6F7890` — digits running 1234567890, letters running
 * ABCDEF, a person walking two keyboards at once. Six of them sit in `docs/`,
 * and because a documented key is neither a fixture nor annotated nor
 * self-describing, those six are every remaining critical on that repository.
 * Detecting the two monotonic runs is easy, and it was written, measured and
 * removed again.
 *
 * It cannot be had. `false-positives.test.ts` pins an `AKIA` prefix followed by
 * `1234567890ABCDEF` as a key that must never be exempted however it is named,
 * and that value *is* a typed sequence — the same shape, indistinguishable by
 * any rule that is not simply a list of the two literals. The header above says
 * why the test is right: the corpus this scanner is measured against builds its
 * fixtures out of exactly these shapes, so a scanner that skips them scores zero
 * on a corpus of real credential formats. Quiet documentation is not worth that
 * trade.
 *
 * The noise is real and stays. It is a cost of keying on value rather than on
 * path, which remains the correct axis — see `isDocPath`.
 */

/**
 * Does a PEM banner have key material under it?
 *
 * The BEGIN banner is a label, not a key. Code that *handles* keys writes the
 * label constantly and never the key (BANNER below stands for the literal
 * banner, which is not written out here because gitleaks' multi-line rule
 * reads three of them in a row as a key block):
 *
 *     const key = stdout.match(/BANNER[\s\S]+?END…/)?.[0];
 *     pem.replace('BANNER', '')
 *     <textarea placeholder="BANNER" />
 *
 * Each of those was a critical, and none was a leak. A committed key always
 * carries its body, so the body is what this requires: a base64 run of at
 * least 40 characters, either on the banner's own line (a key inside a JSON or
 * env string, `\n`-escaped) or on its own line shortly after the banner. The
 * look-ahead leaves room for a legacy encrypted key's `Proc-Type`/`DEK-Info`
 * headers, PGP's `Version:` line and the blank line after them, and for body
 * lines quoted or concatenated as string literals.
 *
 * A banner with no body is dropped, not softened: it is not key material in
 * any context, the same reason `isKnownPlaceholder` drops `AKIA…EXAMPLE`.
 */
const PEM_BODY_LOOKAHEAD = 6;
const PEM_BODY_RUN = /[A-Za-z0-9+/]{40,}/;
const PEM_BODY_LINE = /^[\s'"`+(]*(?:\\n)?[A-Za-z0-9+/]{40,}={0,2}(?:\\n)?['"`,;+)\s]*$/;

export function hasPemBody(lines: readonly string[], index: number, match: RegExpExecArray): boolean {
  const rest = (lines[index] ?? '').slice(match.index + match[0].length).replace(/\\[nr]/g, ' ');
  if (PEM_BODY_RUN.test(rest)) return true;
  const last = Math.min(lines.length - 1, index + PEM_BODY_LOOKAHEAD);
  for (let i = index + 1; i <= last; i++) {
    if (PEM_BODY_LINE.test(lines[i])) return true;
  }
  return false;
}

/** Does the file name a GitHub App id (`GITHUB_APP_ID=123`, `"app_id": 123`, `appId: 123`)? */
const GITHUB_APP_ID = /\b(?:GITHUB_APP_ID|GH_APP_ID|APP_ID|app_id|appId)\b['"]?\s*[=:]\s*['"]?\d{2,}/;

export function hasGithubAppId(lines: readonly string[]): boolean {
  return lines.some((line) => GITHUB_APP_ID.test(line));
}

/** Decode a JWT's payload and check its `role` claim. Never throws. */
export function jwtClaimsRole(token: string, role: string): boolean {
  const payload = token.split('.')[1];
  if (!payload) return false;
  try {
    const b64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const json = JSON.parse(atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4))) as { role?: unknown };
    return json.role === role;
  } catch {
    return false;
  }
}

/**
 * Is a `re_…` token a Resend key rather than an identifier that happens to
 * start with `re_` (Python's `re_` prefix for regex helpers is the common one)?
 * Either the issued layout, or a body with upper case, lower case and digits at
 * key-material entropy. Identifiers are one case or carry no digits.
 */
export function looksLikeResendKey(token: string): boolean {
  if (/^re_[A-Za-z0-9]{8}_[A-Za-z0-9]{16,}$/.test(token)) return true;
  const body = token.slice(3);
  if (!/[a-z]/.test(body) || !/[A-Z]/.test(body) || !/[0-9]/.test(body)) return false;
  return shannonEntropy(body.replace(/_/g, '')) >= 3.5;
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/**
 * Is an unquoted value shaped like issued key material rather than a word,
 * a path or a hex digest? At least 20 characters, at least two of lower /
 * upper / digit, not all hex, not a path or URL, and at least 3.5 bits of
 * entropy per character. `changeme-in-production` has none of the last three.
 */
export function looksLikeKeyMaterial(value: string): boolean {
  if (value.length < 20) return false;
  if (value.startsWith('/') || value.includes('://')) return false;
  if (/^[0-9a-f]+$/i.test(value)) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((re) => re.test(value)).length;
  if (classes < 2) return false;
  return shannonEntropy(value) >= 3.5;
}

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

/**
 * Environment files and their backups, by name: `.env`, `.env.production`,
 * `app.env`, `app.env.bak`, `.env.bak.20261120`, `prod.env.old`. Templates
 * (`.env.example`, `.env.sample`, `.env.template`) are not environment files.
 */
export function isEnvFileName(filename: string): boolean {
  const name = filename.toLowerCase();
  if (/\.(?:example|sample|template|dist|defaults?)$/.test(name)) return false;
  return /^\.env(?:\..*)?$/.test(name) || /\.env$/.test(name) || isEnvBackupName(name);
}

/** A backup copy of an env file: `*.env.bak*`, `.env.old`, `app.env.orig.2`. */
export function isEnvBackupName(filename: string): boolean {
  return /(?:^|\.)env\.(?:bak|old|orig|save|backup|prev|swp)(?:[.~_-].*)?$/i.test(filename) || /\.env~$/i.test(filename);
}

/**
 * A committed dotenv file, by name: `.env`, `.env.*`, `*.env`, `*.env.*`
 * (`.env.bak-2026-07-28`, `.env.production`, `app.env`, `deploy.env.bak-1`).
 *
 * Templates are not dotenv files: any name carrying `.example`, `.sample`,
 * `.template`, `.dist`, `.defaults` or `.schema` anywhere is skipped, so
 * `.env.example.bak` stays quiet too. Neither is source code that merely has
 * `env` in its name (`vite.env.d.ts`, `config.env.js`): the `*.env.*` form is
 * only taken when the trailing extension is not a programming language.
 */
const ENV_TEMPLATE_MARKER = /\.(?:example|sample|template|dist|defaults?|schema)(?:[.\-_~]|$)/;
const SOURCE_EXTENSION = /\.(?:[cm]?[jt]sx?|d\.ts|py|go|rb|rs|java|kts?|php|cs|swift|scala|vue|svelte|astro|json|md|mdx|html?|css|scss)$/;

export function isDotenvFileName(filename: string): boolean {
  const name = filename.toLowerCase();
  if (ENV_TEMPLATE_MARKER.test(name)) return false;
  if (name === '.env' || name.startsWith('.env.')) return true;
  if (name.endsWith('.env') && name.length > 4) return true;
  if (name.includes('.env.')) return !SOURCE_EXTENSION.test(name);
  return false;
}

/** A variable name that announces a credential. */
const SECRET_KEY_NAME = /KEY|SECRET|TOKEN|PASSWORD|PASS|PEPPER|PRIVATE|CREDENTIAL|DSN|AUTH/;
/**
 * Names that carry a secret word but are public by design (`ANON_KEY`,
 * `PUBLISHABLE_KEY`) or hold configuration about a credential rather than the
 * credential (`NEXTAUTH_URL`, `TOKEN_TTL`, `KEYCLOAK_REALM`'s `_ID`s).
 */
const PUBLIC_KEY_NAME = /PUBLIC|ANON|PUBLISHABLE/;
const CONFIG_KEY_SUFFIX =
  /_(?:URL|URI|ENDPOINT|HOST|HOSTNAME|PORT|PATH|DIR|FILE|REGION|ID|NAME|USER|USERNAME|EMAIL|ENABLED|DISABLED|MODE|TYPE|TTL|EXPIRY|EXPIRES(?:_IN)?|TIMEOUT|LENGTH|ALGORITHM|ALG|VERSION|ISSUER|AUDIENCE|PROVIDER|SCOPES?)$/;
/** A URL with a `user:password@` segment is a credential under any name. */
const URL_WITH_CREDENTIALS = /^[a-z][a-z0-9+.-]*:\/\/[^\s/@:]*:[^\s/@]+@/i;

const DOTENV_LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$/;

/** Strip the quotes, or the trailing ` # comment` of an unquoted value. */
function dotenvValue(raw: string): string {
  const trimmed = raw.trim();
  const quoted = /^(['"`])([\s\S]*?)\1/.exec(trimmed);
  if (quoted) return quoted[2];
  return trimmed.replace(/\s+#.*$/, '').trim();
}

/**
 * Is a dotenv value something a template writer typed instead of a secret?
 * `changeme`, `xxx`, `your-api-key`, `<token>`, `${VAR}`, `example`,
 * `placeholder`, `TODO`, `aaaaaaaa`, and anything under 8 characters.
 */
export function isDotenvPlaceholder(value: string): boolean {
  const v = value.trim();
  if (v.length < 8) return true;
  if (/^(.)\1*$/.test(v)) return true;
  if (isVariableReference(v) || /\$\{[^}]*\}/.test(v)) return true;
  if (/^<[^>]*>$/.test(v)) return true;
  if (/^your[-_ ]/i.test(v)) return true;
  if (/changeme|change[-_]me|xxx|example|placeholder|\btodo\b|replace[-_]?me|\*{3,}/i.test(v)) return true;
  return false;
}

export interface CommittedEnvFile {
  /** 0-based index of the first secret-looking line. */
  index: number;
  /** Its variable name: safe to show, unlike its value. */
  key: string;
  /** Secret-looking keys with real-looking values in the file. */
  count: number;
}

/**
 * The `secret-committed-env-file` check: a dotenv file (by name) that holds at
 * least one secret-named key with a value that is not a placeholder.
 *
 * This is the finding the vendor-shaped rules above cannot make. A production
 * `.env` backup carries `DATAFORSEO_PASSWORD=…`, an SMTP password, a session
 * pepper: values no vendor format describes, any of which is a live
 * credential. The name says what the file is and the keys say what it holds,
 * which together are enough; the values themselves are never read out.
 */
export function committedEnvFile(filename: string, lines: readonly string[]): CommittedEnvFile | null {
  if (!isDotenvFileName(filename)) return null;
  let first: { index: number; key: string } | null = null;
  let count = 0;
  lines.forEach((line, index) => {
    const m = DOTENV_LINE.exec(line);
    if (!m) return;
    const key = m[1].toUpperCase();
    const value = dotenvValue(m[2]);
    if (isDotenvPlaceholder(value)) return;
    const credentialUrl = URL_WITH_CREDENTIALS.test(value);
    if (!credentialUrl) {
      if (!SECRET_KEY_NAME.test(key)) return;
      if (PUBLIC_KEY_NAME.test(key) || CONFIG_KEY_SUFFIX.test(key)) return;
    }
    count++;
    if (!first) first = { index, key: m[1] };
  });
  if (!first) return null;
  return { ...(first as { index: number; key: string }), count };
}

export const COMMITTED_ENV_FILE_RULE = {
  id: 'secret-committed-env-file',
  name: 'Committed dotenv file with credentials',
  severity: 'critical' as Severity,
  cwe: 'CWE-538',
  consequence:
    'Every credential in the file is in every clone, fork, CI cache and archive of the repository, and backups are never rotated with the original.',
  fix: 'Rotate every value in the file first (deleting it does not help: it is in the history), then remove it, add the name to .gitignore, and load the values from a secret manager or the deploy environment.',
  reference: attackVector('unrotated-github-app-keys'),
} as const;

/** Files whose mere presence is worth reporting, independent of content. */
export const SENSITIVE_FILES: readonly {
  pattern: string;
  /** When present, matched against the file name instead of `pattern`. */
  test?: (filename: string) => boolean;
  message: string;
  severity: Severity;
}[] = [
  {
    pattern: '.env.bak',
    test: isEnvBackupName,
    message: 'Backup copy of an environment file committed: backups are never rotated with the original',
    severity: 'critical',
  },
  { pattern: '.env', message: 'Environment file committed — the usual home of every runtime credential', severity: 'high' },
  { pattern: '.env.local', message: 'Local environment file committed', severity: 'high' },
  { pattern: '.env.production', message: 'Production environment file committed', severity: 'critical' },
  { pattern: 'id_rsa', message: 'Private SSH key committed', severity: 'critical' },
  { pattern: 'id_ed25519', message: 'Private SSH key committed', severity: 'critical' },
  { pattern: 'id_ecdsa', message: 'Private SSH key committed', severity: 'critical' },
  { pattern: 'id_dsa', message: 'Private SSH key committed', severity: 'critical' },
  { pattern: '.pem', message: 'PEM certificate or key file committed', severity: 'high' },
  { pattern: '.p12', message: 'PKCS#12 keystore committed', severity: 'high' },
  { pattern: '.pfx', message: 'PKCS#12 keystore committed', severity: 'high' },
  { pattern: '.keystore', message: 'Java keystore committed', severity: 'high' },
  // Deliberately not `.npmrc`. Its presence is normal; only an `_authToken`
  // line in it is a credential, and that is a content match, not a filename
  // match. Reporting the file itself trades a real finding for a chore.
];
