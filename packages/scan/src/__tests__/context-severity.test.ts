/**
 * The three structural false-positive causes measured on Go repositories.
 *
 * Every line below is copied from mulgadc/spinifex, an AWS-compatible control
 * plane of 2,439 files that scored 280 findings and zero true positives at
 * 0.11.2. Together these three causes are 200 of those 280.
 *
 * What each of them has in common: the *construct* is genuinely there, so no
 * pattern fix can help. `InsecureSkipVerify: true` really is TLS verification
 * disabled and `"/tmp/test-wal"` really is a predictable path. What is missing
 * is the context that decides whether anyone should care — and a finding
 * nobody should care about, reported at high, is what makes a scanner
 * unpitchable.
 */
import { describe, expect, it } from 'vitest';
import { scanText } from '../text';

const severityOf = (path: string, source: string, ruleId: string): string | undefined =>
  scanText(path, source).find((one) => one.ruleId === ruleId)?.severity;

describe('cause 2 — a construct that is ordinary in a test file', () => {
  // 66 of spinifex's 70 `insecure-temp-file` findings look like this: a table
  // -driven fixture naming a scratch directory. Nothing races anybody for it.
  const WAL = 'func TestVolume(t *testing.T) {\n\tos.OpenFile("/tmp/test-wal", os.O_CREATE, 0600)\n}';

  it('reports a temp path in a _test.go at low', () => {
    expect(severityOf('spinifex/handlers/ec2/volume/service_impl_test.go', WAL, 'insecure-temp-file')).toBe('low');
  });

  it('reports the same line in production code at its own severity', () => {
    expect(severityOf('spinifex/handlers/ec2/volume/service_impl.go', WAL, 'insecure-temp-file')).toBe('medium');
  });

  // `tests/e2e/harness/` is the shape that slipped through: a directory of Go
  // helpers, no `_test.go` suffix on any of them.
  it('reads a test harness directory as a test path', () => {
    const source = 'tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}';
    expect(severityOf('tests/e2e/harness/aws.go', source, 'tls-verification-disabled')).toBe('low');
    expect(severityOf('spinifex/daemon/daemon.go', source, 'tls-verification-disabled')).toBe('high');
  });

  it('says in the message why the severity is what it is', () => {
    const finding = scanText('spinifex/nbd/nbd_test.go', WAL)[0];
    expect(finding?.message).toContain('in a test file');
  });

  // The softening is a claim about severity and nothing else. A repository that
  // wants to audit its own test tree must still be able to find these.
  it('keeps the finding in the report rather than dropping it', () => {
    expect(scanText('spinifex/nbd/nbd_test.go', WAL)).toHaveLength(1);
  });
});

describe('a construct in documentation', () => {
  // A write in a usage example is still a code-shaped match, but nothing in a
  // fenced README block executes it.
  const README = '```js\ncreateWriteStream("/tmp/artifacts/junit.xml")\n```';

  it('reports a temp path in a README at low', () => {
    expect(severityOf('docs/e2e/README.md', README, 'insecure-temp-file')).toBe('low');
  });

  // The credential rules deliberately do not get this treatment — their noise
  // is a property of the value, not the path. `limen-regression.test.ts` owns
  // the other half of this: a real DSN in a README still reports at high.
  it('leaves a credential in documentation at its own severity', () => {
    const leaked = 'DATABASE_URL=postgres://limen_app:Kd93mQpZx2@db.internal:5432/limen';
    expect(severityOf('docs/setup.md', leaked, 'secret-database-url')).toBe('high');
  });
});

describe('cause 3 — a value that repeats the name of the field holding it', () => {
  // Spinifex's `awserrors.go` is 300 lines of these. They are the AWS API's own
  // error codes; `secret-generic-credential` sees the word `Token` beside a
  // quoted string and never looks at what the string is.
  const CODES = [
    'const (',
    '\tErrExpiredToken         = "ExpiredToken"',
    '\tErrInvalidClientTokenId = "InvalidClientTokenId"',
    ')',
  ].join('\n');

  it('drops an error-code constant to low', () => {
    const findings = scanText('spinifex/awserrors/awserrors.go', CODES);
    expect(findings.length).toBeGreaterThan(0);
    for (const one of findings) {
      expect(one.severity).toBe('low');
      expect(one.message).toContain('repeats the name of the field');
    }
  });

  it('drops a URL path and a header name held in a token-shaped name', () => {
    const consts = [
      'pathToken = "/latest/api/token"',
      'hdrToken  = "X-aws-ec2-metadata-token"',
    ].join('\n');
    for (const one of scanText('spinifex/handlers/imds/metadata.go', consts)) {
      expect(one.severity).toBe('low');
    }
  });

  // The hardened path, flagged as the credential. psql's `\getenv` reads the
  // password out of the environment and `:'password'` binds it, so the literal
  // on this line is the *name of the bind parameter*.
  it('drops a psql bind parameter', () => {
    const sql = `ALTER ROLE :"master" WITH LOGIN PASSWORD :'password';`;
    expect(severityOf('cmd/rds-agent/engine.go', sql, 'secret-generic-credential')).toBe('low');
  });

  // The limit of the rule, and the reason it softens rather than skips: this is
  // a real, terrible, hardcoded credential that also happens to echo its key.
  it('still reports a real password that echoes its key', () => {
    const findings = scanText('src/db.go', 'DB_PASSWORD = "password123"');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('secret-generic-credential');
  });

  // Assembled rather than written out, following `foreign-suppression.test.ts`:
  // a credential-shaped literal in this repository is a finding for every other
  // scanner that reads us, and two of them gate our own CI.
  it('leaves a credential that does not echo its key at full severity', () => {
    const value = ['Kd93', 'mQpZ', 'x2Lf'].join('');
    expect(severityOf('src/db.go', `password = "${value}"`, 'secret-generic-credential')).toBe('high');
  });
});

describe('a credential shown as example text', () => {
  it('drops a key in a placeholder attribute to low', () => {
    const jsx = '<input placeholder="AKIAIOSFODNN7EXAMPLE" onChange={onKey} />';
    expect(severityOf('src/routes/login.tsx', jsx, 'secret-aws-access-key')).toBe('low');
  });

  it('drops a PEM banner with no key material under it', () => {
    const jsx = '<textarea placeholder="-----BEGIN PRIVATE KEY-----" />';
    expect(severityOf('src/components/certificate-import-dialog.tsx', jsx, 'secret-private-key')).toBe('low');
  });

  it('leaves the same key at full severity when it is the value', () => {
    const jsx = '<input defaultValue="AKIAIOSFODNN7EXAMPLE" onChange={onKey} />';
    expect(severityOf('src/routes/login.tsx', jsx, 'secret-aws-access-key')).toBe('critical');
  });
});
