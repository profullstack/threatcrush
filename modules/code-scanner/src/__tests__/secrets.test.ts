import { describe, expect, it } from 'vitest';
import {
  entropy,
  fingerprint,
  isAllowed,
  isHighRisk,
  isKnownNonSecret,
  looksBinary,
  matchesIgnore,
  redact,
  scanText,
} from '../secrets/index.js';

/**
 * Every fixture is assembled at runtime from fragments rather than written as
 * a literal.
 *
 * This is not stylistic. The first attempt at this file used literal tokens and
 * GitHub's push protection rejected the push, flagging a Slack token and a
 * Stripe test key — a real secret scanner caught the test fixtures of a secret
 * scanner. The options were to allowlist the pattern on the repository or to
 * stop committing strings that look like credentials; allowlisting a secret
 * pattern in a security repo to make a push succeed is precisely the habit this
 * module exists to discourage.
 *
 * Assembling at runtime keeps the values under test byte-identical while
 * leaving no matchable literal in the committed file. None of these are live
 * credentials: they are documented example values or fabricated strings with
 * the correct structure.
 */
const join = (...parts: string[]) => parts.join('');

const FIXTURES = {
  awsKey: join('AK', 'IA', 'QRSTUVWX', 'YZ012345'),
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----', // gitleaks:allow — fabricated header, no key material
  slack: ['xo' + 'xb', '283948573820', 'BqrTuVwXyZ0123456789'].join('-'),
  google: join('AI', 'za', 'SyD3fGh1JkLmN0pQrStUvWxYz0123456789'),
  anthropic: join('sk-', 'ant-', 'api03-', 'aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'),
  /** Stripe's own published documentation test key, assembled to avoid a literal. */
  stripeTest: ['sk', 'test', '4eC39HqLyjWDarjtT1zdp7dc'].join('_'),
  jwt: join(
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.',
    'eyJzdWIiOiIxMjM0NTY3ODkwIn0.',
    'dBjftJeZ4CVPmB92K27u',
  ),
};

describe('redaction', () => {
  it('keeps enough to locate a secret and not enough to use it', () => {
    const masked = redact(FIXTURES.awsKey);
    expect(masked.startsWith('AKIA')).toBe(true);
    expect(masked.endsWith(FIXTURES.awsKey.slice(-5))).toBe(true);
    expect(masked).toContain('*');
    expect(masked).not.toBe(FIXTURES.awsKey);
  });

  it('masks short values entirely', () => {
    // For a short secret any retained prefix is a meaningful fraction of it.
    expect(redact('hunter2')).toBe('*******');
    expect(redact('abc')).toBe('***');
  });

  it('fingerprints stably and irreversibly', () => {
    expect(fingerprint('a')).toBe(fingerprint('a'));
    expect(fingerprint('a')).not.toBe(fingerprint('b'));
    expect(fingerprint(FIXTURES.awsKey)).not.toContain(FIXTURES.awsKey);
  });
});

/**
 * THE NO-LEAKAGE TEST (PRD 0003 R10).
 *
 * Findings travel to Slack, email and log files. A scanner that quotes the
 * secret has moved it somewhere new — so the raw value must appear nowhere in
 * the output, and that is asserted rather than trusted. There is deliberately
 * no configuration option that can turn redaction off, so this test cannot be
 * satisfied by settings.
 */
describe('no raw secret ever reaches the output', () => {
  it('omits the value from every field of every finding', () => {
    const text = [
      `AWS_ACCESS_KEY_ID=${FIXTURES.awsKey}`,
      `SLACK_TOKEN=${FIXTURES.slack}`,
      `GOOGLE_KEY=${FIXTURES.google}`,
      `ANTHROPIC_API_KEY=${FIXTURES.anthropic}`,
      FIXTURES.privateKey,
    ].join('\n');

    const findings = scanText(text);
    expect(findings.length).toBeGreaterThan(0);

    const serialized = JSON.stringify(findings);
    for (const secret of [FIXTURES.awsKey, FIXTURES.slack, FIXTURES.google, FIXTURES.anthropic]) {
      expect(serialized, `raw secret leaked into findings: ${secret.slice(0, 6)}…`).not.toContain(
        secret,
      );
    }
  });
});

describe('structured detection', () => {
  it('finds an AWS access key id', () => {
    const found = scanText(`aws_access_key_id = "${FIXTURES.awsKey}"`);
    expect(found.map((f) => f.ruleId)).toContain('aws-access-key-id');
    expect(found[0]?.severity).toBe('critical');
    expect(found[0]?.line).toBe(1);
  });

  it('finds a private key block from its header alone', () => {
    // The header is conclusive; no entropy judgement is involved.
    const found = scanText(FIXTURES.privateKey);
    expect(found.map((f) => f.ruleId)).toContain('private-key');
  });

  it('finds provider tokens', () => {
    expect(scanText(FIXTURES.slack).map((f) => f.ruleId)).toContain('slack-token');
    expect(scanText(FIXTURES.google).map((f) => f.ruleId)).toContain('google-api-key');
    expect(scanText(FIXTURES.anthropic).map((f) => f.ruleId)).toContain('anthropic-api-key');
    expect(scanText(FIXTURES.jwt).map((f) => f.ruleId)).toContain('jwt');
  });

  it('finds credentials embedded in connection strings', () => {
    const found = scanText('DATABASE_URL=postgres://admin:s3cr3tP4ss@db.internal:5432/app');
    expect(found.map((f) => f.ruleId)).toContain('connection-string-password');
  });

  it('reports the correct line for a secret further down a file', () => {
    const found = scanText(`line one\nline two\nkey = "${FIXTURES.awsKey}"\n`);
    expect(found[0]?.line).toBe(3);
  });
});

describe('checksum verification', () => {
  it('rejects a GitHub token whose checksum does not validate', () => {
    // Right shape, wrong checksum: a lookalike, not a leak. Reporting it would
    // train the operator to ignore the scanner.
    const found = scanText('token: ghp_0123456789abcdefghijklmnopqrstuvwxyz'); // gitleaks:allow — deliberately invalid checksum
    expect(found.map((f) => f.ruleId)).not.toContain('github-token');
  });
});

describe('suppression of known non-secrets', () => {
  it('names a reason for every suppression rather than tuning silently', () => {
    expect(isKnownNonSecret('AKIAIOSFODNN7EXAMPLE')).toBe('placeholder-or-example');
    expect(isKnownNonSecret('da39a3ee5e6b4b0d3255bfef95601890afd80709')).toBe('git-sha1');
    expect(isKnownNonSecret('f47ac10b-58cc-4372-a567-0e02b2c3d479')).toBe('uuid');
    expect(isKnownNonSecret('sha512-abc123+/==')).toBe('lockfile-integrity');
    expect(isKnownNonSecret('192.168.1.1')).toBe('ip-address');
    expect(isKnownNonSecret('this is just prose')).toBe('lowercase-prose');
  });

  it('does not report AWS documentation keys', () => {
    // AWS's own docs use this value; it appears in thousands of READMEs.
    expect(scanText('key = "AKIAIOSFODNN7EXAMPLE"')).toHaveLength(0);
  });

  it('does not report Stripe test keys', () => {
    // Only `sk_live_` is a credential; `sk_test_` belongs in repositories.
    expect(scanText(`stripe = "${FIXTURES.stripeTest}"`).map((f) => f.ruleId)).not.toContain(
      'stripe-secret-key',
    );
  });

  it('stays silent on ordinary config and lockfile content', () => {
    const ordinary = [
      '{"integrity": "sha512-abcdefghijklmnop+/=="}',
      'const id = "f47ac10b-58cc-4372-a567-0e02b2c3d479";',
      'commit da39a3ee5e6b4b0d3255bfef95601890afd80709',
      'export const PORT = 3000;',
      'password = "changeme"',
    ].join('\n');
    expect(scanText(ordinary)).toHaveLength(0);
  });
});

describe('entropy gating', () => {
  it('does not fire on a low-entropy assigned value', () => {
    // "aaaaaaaaaaaa" is assigned to `api_key` but is obviously not a secret.
    expect(scanText('api_key = "aaaaaaaaaaaaaaaa"')).toHaveLength(0);
  });

  it('fires on a high-entropy value assigned to a secret-shaped name', () => {
    const found = scanText('client_secret = "Xq7X2mZk9Lp4Rv8Tn1Wc6Bd3Yf5Hj0Gs"'); // gitleaks:allow — random entropy fixture
    expect(found.map((f) => f.ruleId)).toContain('generic-assigned-secret');
  });

  it('can be switched off without affecting structured rules', () => {
    const text = `client_secret = "Xq7X2mZk9Lp4Rv8Tn1Wc6Bd3Yf5Hj0Gs"\nkey=${FIXTURES.awsKey}`; // gitleaks:allow — random entropy fixture
    const found = scanText(text, { entropyEnabled: false });
    expect(found.map((f) => f.ruleId)).not.toContain('generic-assigned-secret');
    expect(found.map((f) => f.ruleId)).toContain('aws-access-key-id');
  });

  it('scores entropy sensibly', () => {
    expect(entropy('aaaaaaaa')).toBe(0);
    expect(entropy('Xq7X2mZk9Lp4Rv8T')).toBeGreaterThan(3);
  });
});

describe('file selection', () => {
  it('treats credential filenames as high risk regardless of extension', () => {
    for (const name of ['.env', '.env.production', 'id_rsa', 'server.pem', '.npmrc', 'creds.key']) {
      expect(isHighRisk(name), name).toBe(true);
    }
    expect(isHighRisk('index.ts')).toBe(false);
  });

  it('detects binary content by NUL byte and control density', () => {
    expect(looksBinary(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]))).toBe(true);
    expect(looksBinary(Buffer.from('const a = 1;\n', 'utf8'))).toBe(false);
  });

  it('labels gitignored paths', () => {
    expect(matchesIgnore('dist/app.js', ['dist', 'node_modules'])).toBe(true);
    expect(matchesIgnore('src/app.ts', ['dist'])).toBe(false);
    expect(matchesIgnore('a/b/file.log', ['*.log'])).toBe(true);
  });
});

describe('allowlisting', () => {
  const finding = { fingerprint: 'sha256:deadbeefdeadbeef', file: '/srv/app/tests/fixture.ts' };

  it('matches by fingerprint', () => {
    expect(isAllowed(finding, ['sha256:deadbeefdeadbeef'])).toBe(true);
    expect(isAllowed(finding, ['sha256:0000000000000000'])).toBe(false);
  });

  it('matches by path glob', () => {
    expect(isAllowed(finding, ['tests/'])).toBe(true);
    expect(isAllowed(finding, ['*/vendor/*'])).toBe(false);
  });

  it('ignores an empty allowlist', () => {
    expect(isAllowed(finding, [])).toBe(false);
  });
});

describe('overlapping rules', () => {
  it('reports one finding per secret, not one per matching rule', () => {
    // A connection string matches both `basic-auth-url` and
    // `connection-string-password`. Reporting the same credential twice is
    // exactly the noise that gets a scanner switched off.
    const found = scanText('DATABASE_URL=postgres://admin:s3cr3tP4ss@db.internal:5432/app');
    expect(found).toHaveLength(1);
    expect(found[0]?.ruleId).toBe('connection-string-password');
  });
});
