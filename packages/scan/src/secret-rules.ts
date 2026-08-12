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
  },
  {
    id: 'secret-generic-credential',
    name: 'Hardcoded Credential',
    pattern: /(?:secret|password|passwd|pwd|token)\s*[=:]\s*['"]([^'"\s]{8,})['"]/i,
    severity: 'high',
    cwe: 'CWE-798',
    consequence: 'A password in source is a password in every clone, fork and CI cache of that source.',
  },
  {
    id: 'secret-hex-token',
    name: 'High-entropy Hex Token',
    pattern: /(?:token|key|secret|auth|signing)\w*\s*[=:]\s*['"]?([0-9a-f]{32,})['"]?/i,
    severity: 'medium',
    cwe: 'CWE-798',
    consequence: 'Signing secrets and session keys are usually hex; a leaked one forges anything they sign.',
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
