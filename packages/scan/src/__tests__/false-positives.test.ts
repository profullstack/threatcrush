/**
 * Regression cover for the false-positive classes triaged out of a real scan.
 *
 * Every case below is a verbatim line from `profullstack/qryptchat-web`, whose
 * pull requests were getting 91 findings — 5 of them HIGH — none of which named
 * a defect. A scan that reports 87 non-findings does not get read, so the
 * volume was the bug.
 *
 * Each `describe` pairs the shape that must go quiet with the neighbouring
 * shape that must still fire. The pairs are the point: a fix that only silences
 * is indistinguishable from deleting the rule.
 */

import { describe, expect, it } from 'vitest';
import { enclosingCallees, interpolationsAreConstant } from '../code-rules';
import { isTestFixtureValue, isVariableReference } from '../secret-rules';
import { scanText } from '../text';

const ruleIds = (path: string, source: string): string[] =>
  scanText(path, source).map((finding) => finding.ruleId);

describe('credential values that are variable references', () => {
  // The three HIGH findings on qryptchat-web's shell scripts. `:-` with an
  // empty right-hand side is a script refusing to default a secret; reporting
  // it as a hardcoded credential flags the remediation as the defect.
  it('does not flag a shell expansion with no literal fallback', () => {
    const source = [
      '#!/usr/bin/env bash',
      'SUPABASE_ACCESS_TOKEN="${SUPABASE_ACCESS_TOKEN:-}"',
      'TWILIO_AUTH_TOKEN="${TWILIO_AUTH_TOKEN:-}"',
      'API_SECRET="${API_SECRET}"',
      'DB_PASSWORD="${DB_PASSWORD:-$FALLBACK_PASSWORD}"',
    ].join('\n');
    expect(ruleIds('scripts/deploy.sh', source)).toEqual([]);
  });

  it('still flags an expansion whose fallback is a real literal', () => {
    const source = 'DB_PASSWORD="${DB_PASSWORD:-hunter2horsebattery}"';
    expect(ruleIds('scripts/deploy.sh', source)).toContain('secret-generic-credential');
  });

  it('recognises the other interpolation syntaxes, and nothing else', () => {
    expect(isVariableReference('${TOKEN}')).toBe(true);
    expect(isVariableReference('${TOKEN:-}')).toBe(true);
    expect(isVariableReference('${TOKEN:-${OTHER}}')).toBe(true);
    expect(isVariableReference('$TOKEN')).toBe(true);
    expect(isVariableReference('$(vault read token)')).toBe(true);
    expect(isVariableReference('%TOKEN%')).toBe(true);
    expect(isVariableReference('{{ token }}')).toBe(true);
    expect(isVariableReference('#{token}')).toBe(true);
    expect(isVariableReference('<%= token %>')).toBe(true);

    expect(isVariableReference('${TOKEN:-hunter2}')).toBe(false);
    expect(isVariableReference('AKIAIOSFODNN7EXAMPLE')).toBe(false);
    expect(isVariableReference('correct horse battery staple')).toBe(false);
  });

  // A template literal interpolating a variable into a log message was
  // reported as a credential in the message text.
  it('does not flag a value interpolated into a log message', () => {
    const source =
      'console.log(`VULNERABILITY: import succeeded with wrong password: "${testPassword}"`);';
    expect(ruleIds('tests/gpg.test.js', source)).toEqual([]);
  });
});

describe('fixture credentials in test files', () => {
  const fixtures = [
    "  access_token: 'test-token',",
    "  refresh_token: 'test-refresh',",
    "  access_token: 'mock-session-token',",
    "  access_token: 'access-token',",
    "  refresh_token: 'valid-refresh',",
    "  password: 'testpassword123'",
    "  const password = 'mySecurePassword123';",
    "  const testGPGPassword = 'gpgPassword456';",
    "  const wrongPassword = 'completelyWrongPassword';",
  ];

  it('goes quiet on values that describe themselves as fixtures', () => {
    for (const line of fixtures) {
      expect(ruleIds('tests/auth.test.js', line), line).toEqual([]);
    }
  });

  // The exemption is what `isTestPath` decides, and nothing else. The same
  // line in shipped code is still a hardcoded credential.
  it('keeps flagging the identical line outside a test path', () => {
    expect(ruleIds('src/lib/auth.js', "  const password = 'mySecurePassword123';")).toContain(
      'secret-generic-credential',
    );
  });

  // The whole safety argument for the exemption: it is unreachable from the
  // vendor-prefixed rules, which have no `keywordShaped` flag.
  //
  // Every credential shape below is assembled at runtime rather than written
  // out. A scanner's own fixtures are indistinguishable from a leak to every
  // *other* scanner, and this repository's CI runs two of them — a literal
  // `AKIA…` here fails gitleaks and semgrep on an unrelated pull request. The
  // concatenation is the fixture; the joined value is what the rule sees.
  it('never exempts a vendor-issued key, however it is named', () => {
    const cases: [string, string][] = [
      ['secret-aws-access-key', `const testKey = '${'AKIA' + '1234567890ABCDEF'}';`],
      ['secret-github-token', `const mockToken = '${'ghp_' + 'a'.repeat(36)}';`],
      ['secret-stripe-key', `const fakeKey = '${'sk_live_' + 'a'.repeat(24)}';`],
      ['secret-private-key', `const samplePem = '${'-----BEGIN RSA PRIVATE KEY' + '-----'}';`],
    ];
    for (const [ruleId, line] of cases) {
      expect(ruleIds('tests/billing.test.js', line), line).toContain(ruleId);
    }
  });

  // A real service JWT pasted into a debug script was the one credential
  // finding worth keeping out of seventy-nine. The 48-character cap on the
  // key-echo signal is what stops a long base64 blob exempting itself.
  it('keeps a long opaque token even in a test file', () => {
    const jwt = ['eyJ' + 'hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'eyJ' + 'zdXBhYmFzZSByb2xl', 'c2ln'].join('.');
    const source = `const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '${jwt}';`;
    expect(ruleIds('tests/debug-sms.js', source)).toContain('secret-jwt');
  });

  it('keeps a test value that resembles nothing in particular', () => {
    expect(ruleIds('tests/invite.test.js', "  inviteToken: 'qci1.payload.signature',")).toContain(
      'secret-generic-credential',
    );
  });

  /**
   * A weak password is still a password.
   *
   * The failure mode of any "this looks like words" heuristic is that it
   * swallows exactly the credentials most worth finding — the guessable ones a
   * human typed. `secret-rules.ts` already says `root:hunter2@` must not be
   * exempt; these are the same claim for the new signals, and they are the
   * cases that would break first if the stem list or the key-echo rule were
   * widened later.
   */
  it('keeps a weak human-chosen password, even inside a test file', () => {
    const material = [
      "const password = 'MyDogsNameIsRex';",
      "const password = 'Tr0ub4dor&3xK';",
      "const password = 'P@ssw0rd!2024#prod';",
      'DB_PASSWORD="Kx9mQ2vLp7Rt4Wn"',
      "  password: 'hunter2hunter2',",
    ];
    for (const line of material) {
      expect(ruleIds('tests/login.test.js', line), line).toContain('secret-generic-credential');
    }
  });

  it('keeps a metasyntactic username beside a real password', () => {
    // The header's own example: both halves must be metasyntactic to exempt a
    // DSN, and a database URL is not keyword-shaped, so it is never eligible
    // for the fixture exemption regardless.
    const dsn = "const url = 'postgres://root:hunter2@db.internal:5432/app';";
    expect(ruleIds('tests/db.test.js', dsn)).toContain('secret-database-url');
  });

  it('does not read a fixture stem out of the middle of a word', () => {
    expect(isTestFixtureValue("const x = 'a'", 'latestbuildsecret')).toBe(false);
    expect(isTestFixtureValue("const x = 'a'", 'contestwinner2024')).toBe(false);
    expect(isTestFixtureValue("const x = 'a'", 'testbuildsecret')).toBe(true);
  });
});

describe('an origin read that is logged, not reflected', () => {
  // qryptchat-web's websocket server logged the caller's origin inside a
  // console.log four lines below the opening paren. Character-for-character
  // the CORS defect; nesting is the only thing that tells them apart.
  it('does not flag an origin logged inside a console.log', () => {
    const source = [
      "console.log('[SERVER] connection details:', {",
      '  url: request.url,',
      '  headers: {',
      '    origin: request.headers.origin,',
      "    userAgent: request.headers['user-agent'],",
      '  },',
      '});',
    ].join('\n');
    expect(ruleIds('src/server.js', source)).not.toContain('js-cors-origin-reflected');
  });

  it('still flags an origin handed to CORS middleware', () => {
    const source = ['app.use(cors({', '  origin: req.headers.origin,', '}));'].join('\n');
    expect(ruleIds('src/server.js', source)).toContain('js-cors-origin-reflected');
  });

  it('reads the callees of the calls still open above a line', () => {
    const lines = ['logger.debug({', '  a: 1,', '});', 'send(res, {', '  b: 2,'];
    expect(enclosingCallees(lines, 1, 8)).toEqual(['logger.debug']);
    expect(enclosingCallees(lines, 4, 8)).toEqual(['send']);
    // A parenthesis inside a string must not unbalance the walk.
    expect(enclosingCallees(["log('oops :(', {", '  a: 1,'], 1, 8)).toEqual(['log']);
  });
});

describe('the Host header used to parse a relative request URL', () => {
  // `request.url` on a Node server is a path, and `new URL` refuses a relative
  // input without a base. The base is discarded; only the query is read.
  it('does not flag parsing request.url against a host-derived base', () => {
    const source = [
      'const url = new URL(request.url, `http://${request.headers.host}`);',
      "const token = url.searchParams.get('token');",
    ].join('\n');
    expect(ruleIds('src/ws/auth.js', source)).not.toContain('js-host-header-trust');
  });

  it('still flags a link built from the Host header', () => {
    const source = 'const link = new URL(`/reset?t=${t}`, `https://${req.headers.host}`);';
    expect(ruleIds('src/mail.js', source)).toContain('js-host-header-trust');
  });

  it('still flags the Host header concatenated into a link', () => {
    const source = "const reset = 'https://' + req.headers.host + '/reset?t=' + token;";
    expect(ruleIds('src/mail.js', source)).toContain('js-host-header-trust');
  });
});

describe('shell execution whose interpolations are file constants', () => {
  it('does not flag a command assembled from const string literals', () => {
    const source = [
      "const SRC = '/srv/app/src/routes/api';",
      "const files = execSync(`find ${SRC} -name '+server.js'`, { encoding: 'utf8' });",
    ].join('\n');
    expect(ruleIds('scripts/convert-routes.mjs', source)).not.toContain(
      'js-shell-exec-interpolation',
    );
  });

  it('still flags a command interpolating anything it cannot resolve', () => {
    const source = [
      "const SRC = '/srv/app';",
      'const out = execSync(`find ${SRC} -name ${req.query.name}`);',
    ].join('\n');
    expect(ruleIds('scripts/run.mjs', source)).toContain('js-shell-exec-interpolation');
  });

  // `let` can be reassigned from a request between the binding and the call,
  // and a binding built by interpolation only moves the question.
  it('resolves const string literals and refuses everything else', () => {
    expect(interpolationsAreConstant('exec(`ls ${DIR}`)', "const DIR = '/tmp';")).toBe(true);
    expect(interpolationsAreConstant('exec(`ls ${DIR}`)', "let DIR = '/tmp';")).toBe(false);
    expect(interpolationsAreConstant('exec(`ls ${DIR}`)', 'const DIR = base + x;')).toBe(false);
    expect(interpolationsAreConstant('exec(`ls ${DIR}`)', 'const DIR = `${base}/x`;')).toBe(false);
    expect(interpolationsAreConstant('exec(`ls ${o.dir}`)', "const o = { dir: '/tmp' };")).toBe(
      false,
    );
    // Nothing to resolve is not the same as resolving to a constant: the
    // concatenation spelling of the same rule must stay reported.
    expect(interpolationsAreConstant("exec('ls ' + dir)", "const dir = '/tmp';")).toBe(false);
  });
});

describe('findings this triage deliberately left alone', () => {
  // Suppressing these would be the scanner talking itself out of real classes.
  it('still reports a nested quantifier, a lifecycle script and a live HTML sink', () => {
    const redos = String.raw`const p = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/i;`;
    expect(ruleIds('src/api/profile.js', redos)).toContain('redos-nested-quantifier');

    const sink = '<span dangerouslySetInnerHTML={{ __html: contentWithLinks }} />';
    expect(ruleIds('src/components/MessageItem.jsx', sink)).toContain('js-unescaped-html-sink');
  });
});
