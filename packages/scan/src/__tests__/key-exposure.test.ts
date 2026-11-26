import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { scanPath } from '../node/walk';
import {
  committedEnvFile,
  isDotenvFileName,
  isDotenvPlaceholder,
  isEnvBackupName,
  isEnvFileName,
  jwtClaimsRole,
  looksLikeResendKey,
  looksLikeKeyMaterial,
  SECRET_RULES,
} from '../secret-rules';
import { scanText } from '../text';

/**
 * Exposed keys and credentials of any type, anywhere in a tree.
 *
 * Every key-shaped value in this file is FAKE and assembled at runtime: a
 * literal would fail the other secret scanners in this repository's CI, and
 * the point of a fixture is that it can never authenticate anything.
 */
const BEGIN = (kind = '') => `-----BEGIN ${kind}PRIVATE KEY` + '-----';
const END = (kind = '') => `-----END ${kind}PRIVATE KEY` + '-----';
const FAKE_BODY = ['FAKEKEYFORTESTS', 'ONLYFAKEKEYFORT', 'ESTSONLYFAKEKEY'].join('');
const pem = (kind = '') => [BEGIN(kind), FAKE_BODY, FAKE_BODY, END(kind)].join('\n');

const ids = (path: string, source: string) => scanText(path, source).map((f) => f.ruleId);
const secretIds = (path: string, source: string) =>
  scanText(path, source).filter((f) => f.category === 'secret').map((f) => f.ruleId);

describe('PEM private keys in every packaging', () => {
  for (const kind of ['', 'RSA ', 'EC ', 'OPENSSH ', 'DSA ', 'ENCRYPTED ']) {
    it(`finds a bare ${kind || 'PKCS#8 '}block`, () => {
      expect(secretIds('keys/server.txt', pem(kind))).toContain('secret-private-key');
    });
  }

  it('finds a key inside a quoted multi-line env value', () => {
    const source = [`SIGNING_KEY="${BEGIN('RSA ')}`, FAKE_BODY, FAKE_BODY, `${END('RSA ')}"`].join('\n');
    expect(secretIds('deploy/app.env', source)).toContain('secret-private-key');
  });

  it('finds a \\n-escaped one-line key', () => {
    const source = `PRIVATE_KEY="${BEGIN()}\\n${FAKE_BODY}\\n${FAKE_BODY}\\n${END()}\\n"`;
    expect(secretIds('config/prod.env', source)).toContain('secret-private-key');
  });

  it('finds a key in a JSON string', () => {
    const source = `{ "private_key": "${BEGIN()}\\n${FAKE_BODY}\\n${END()}\\n" }`;
    expect(secretIds('svc-account.json', source)).toContain('secret-private-key');
  });

  it('stays silent on a banner with no body (code that handles keys)', () => {
    const source = `if (!pem.startsWith('${BEGIN('RSA ')}')) throw new Error('not a key');`;
    expect(secretIds('src/keys.ts', source)).toEqual([]);
  });

  it('never echoes the key body in a finding', () => {
    const source = `PRIVATE_KEY="${BEGIN()}\\n${FAKE_BODY}\\n${END()}\\n"`;
    const finding = scanText('app.env', source).find((f) => f.ruleId === 'secret-private-key')!;
    expect(finding.excerpt).not.toContain(FAKE_BODY);
    expect(finding.sensitive).toBe(true);
  });
});

describe('GitHub App private keys', () => {
  it('names a private key beside GITHUB_APP_ID as a GitHub App key, once', () => {
    const source = ['GITHUB_APP_ID=123456', `GITHUB_APP_PRIVATE_KEY="${BEGIN('RSA ')}\\n${FAKE_BODY}\\n${END('RSA ')}"`].join('\n');
    const found = secretIds('apps/bot/app.env', source);
    expect(found).toContain('secret-github-app-private-key');
    // Superseded, not reported twice.
    expect(found).not.toContain('secret-private-key');
  });

  it('accepts APP_ID and a JSON app_id', () => {
    expect(secretIds('a.env', ['APP_ID=98765', pem('RSA ')].join('\n'))).toContain('secret-github-app-private-key');
    expect(secretIds('a.json', [`{"app_id": 4242,`, `"key": "${BEGIN()}\\n${FAKE_BODY}\\n${END()}"}`].join('\n'))).toContain(
      'secret-github-app-private-key',
    );
  });

  it('carries a fix and the attack-vector reference', () => {
    const source = ['GITHUB_APP_ID=123456', pem('RSA ')].join('\n');
    const finding = scanText('app.env', source).find((f) => f.ruleId === 'secret-github-app-private-key')!;
    expect(finding.severity).toBe('critical');
    expect(finding.fix).toMatch(/delete every old key/);
    expect(finding.reference).toMatch(/attack-vectors\/unrotated-github-app-keys\.md$/);
  });

  it('is a plain private key without an App id', () => {
    const found = secretIds('a.env', pem('RSA '));
    expect(found).toContain('secret-private-key');
    expect(found).not.toContain('secret-github-app-private-key');
  });
});

describe('vendor token formats', () => {
  const cases: Array<[string, string]> = [
    ['secret-github-token', 'ghp_' + 'FAKE'.repeat(9)],
    ['secret-github-token', 'gho_' + 'FAKE'.repeat(9)],
    ['secret-github-token', 'ghu_' + 'FAKE'.repeat(9)],
    ['secret-github-token', 'ghs_' + 'FAKE'.repeat(9)],
    ['secret-github-token', 'ghr_' + 'FAKE'.repeat(9)],
    ['secret-github-token', 'github_pat_' + 'FAKE_'.repeat(13)],
    ['secret-aws-access-key', 'AKIA' + 'FAKEFAKEFAKEFAKE'],
    ['secret-slack-token', 'xoxb-' + '1234567890-FAKE'],
    ['secret-slack-token', 'xoxp-' + '1234567890-FAKE'],
    ['secret-stripe-key', 'sk_live_' + 'FAKE'.repeat(6)],
    ['secret-resend-key', 're_' + 'FAKE1234' + '_' + 'FAKEfakeFAKEfakeFAKE'],
    ['secret-openai-key', 'sk-' + 'FAKE'.repeat(9)],
  ];
  for (const [rule, value] of cases) {
    it(`${rule} matches ${value.slice(0, 6)}...`, () => {
      expect(secretIds('src/config.ts', `const key = "${value}";`)).toContain(rule);
    });
  }

  it('redacts every vendor token in the excerpt', () => {
    const value = 'ghp_' + 'FAKE'.repeat(9);
    const finding = scanText('src/config.ts', `token: ${value}`).find((f) => f.ruleId === 'secret-github-token')!;
    expect(finding.excerpt).not.toContain(value);
  });

  it('the pattern table is the extension point: every entry is complete', () => {
    for (const rule of SECRET_RULES) {
      expect(rule.id).toMatch(/^secret-[a-z0-9-]+$/);
      expect(rule.pattern).toBeInstanceOf(RegExp);
      expect(rule.consequence.length).toBeGreaterThan(10);
      expect(rule.cwe).toMatch(/^CWE-\d+$/);
    }
    expect(new Set(SECRET_RULES.map((r) => r.id)).size).toBe(SECRET_RULES.length);
  });
});

describe('Supabase service-role JWTs', () => {
  const b64url = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const jwt = (role: string) =>
    [b64url({ alg: 'HS256', typ: 'JWT' }), b64url({ iss: 'supabase-FAKE', role, iat: 1 }), 'FAKEsignatureFAKEsignature'].join('.');

  it('decodes the role claim', () => {
    expect(jwtClaimsRole(jwt('service_role'), 'service_role')).toBe(true);
    expect(jwtClaimsRole(jwt('anon'), 'service_role')).toBe(false);
    expect(jwtClaimsRole('not.a.jwt', 'service_role')).toBe(false);
  });

  it('reports a service-role key as critical, once', () => {
    const found = scanText('.env', `SUPABASE_SERVICE_ROLE_KEY=${jwt('service_role')}`).filter(
      (f) => f.category === 'secret' && f.ruleId !== 'secret-committed-env-file',
    );
    expect(found.map((f) => f.ruleId)).toEqual(['secret-supabase-service-role']);
    expect(found[0]!.severity).toBe('critical');
  });

  it('does not call the anon key a service-role key', () => {
    const found = secretIds('.env', `NEXT_PUBLIC_SUPABASE_ANON_KEY=${jwt('anon')}`);
    expect(found).not.toContain('secret-supabase-service-role');
    expect(found).not.toContain('secret-generic-high-entropy');
  });
});

describe('generic *_SECRET / *_PRIVATE_KEY / *_TOKEN with high entropy', () => {
  const random = ['FAKEq9xQ2', 'mZ7pL4vR8', 'tW1nB6cY3hJ'].join('');

  it('flags unquoted high-entropy values under secret-shaped names', () => {
    for (const name of ['WEBHOOK_SECRET', 'SESSION_SECRET_KEY', 'SIGNER_PRIVATE_KEY', 'DEPLOY_TOKEN', 'MAILER_API_KEY', 'DB_PASSWORD']) {
      expect(secretIds('deploy/app.env', `${name}=${random}`), name).toContain('secret-generic-high-entropy');
    }
    expect(secretIds('deploy/app.env', `export WEBHOOK_SECRET=${random}`)).toContain('secret-generic-high-entropy');
  });

  it('leaves words, paths, URLs, hex and public values alone', () => {
    const quiet = [
      'ADMIN_PASSWORD=changeme-in-production-please',
      'DATABASE_PASSWORD_FILE=/run/secrets/database-password',
      'AWS_ROLE_ARN=arn:aws:iam::123456789012:role/app-runtime',
      'CALLBACK_SECRET=https://example.invalid/callback/path',
      `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY_TOKEN=${random}`,
      'WEBHOOK_SECRET=${WEBHOOK_SECRET}',
      'WEBHOOK_SECRET=',
    ];
    for (const line of quiet) expect(secretIds('app.env', line), line).not.toContain('secret-generic-high-entropy');
    // All-hex belongs to the existing hex rule, not this one.
    const hex = secretIds('app.env', 'SIGNING_SECRET=' + '0123456789abcdef'.repeat(2));
    expect(hex).toContain('secret-hex-token');
    expect(hex).not.toContain('secret-generic-high-entropy');
  });

  it('yields to a vendor rule on the same line', () => {
    const found = secretIds('app.env', `GITHUB_TOKEN=${'ghp_' + 'FAKE'.repeat(9)}`);
    expect(found).toContain('secret-github-token');
    expect(found).not.toContain('secret-generic-high-entropy');
  });

  it('measures key material, not vibes', () => {
    expect(looksLikeKeyMaterial(random)).toBe(true);
    expect(looksLikeKeyMaterial('aaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe(false);
    expect(looksLikeKeyMaterial('Password1Password1Password1')).toBe(false);
  });
});

describe('env files and backups by name', () => {
  it('recognises env files and their backups', () => {
    for (const name of ['.env', '.env.production', 'app.env', 'app.env.bak', 'app.env.bak.20261120', '.env.bak', 'prod.env.old', 'api.env.orig', '.env~']) {
      expect(isEnvFileName(name), name).toBe(true);
    }
    for (const name of ['.env.example', 'app.env.sample', '.env.template', 'environment.ts', 'envoy.yaml']) {
      expect(isEnvFileName(name), name).toBe(false);
    }
    expect(isEnvBackupName('app.env.bak.2')).toBe(true);
    expect(isEnvBackupName('app.env')).toBe(false);
  });
});

describe('scanPath: committed key and env files', () => {
  const root = mkdtempSync(join(tmpdir(), 'tc-keys-'));
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  const write = (rel: string, text: string) => {
    mkdirSync(join(root, rel, '..'), { recursive: true });
    writeFileSync(join(root, rel), text);
  };
  write('deploy/id_rsa', 'not a real key, FAKE fixture\n');
  write('deploy/id_ed25519', 'not a real key, FAKE fixture\n');
  write('certs/server.pem', 'FAKE\n');
  write('apps/bot/app.env', 'LOG_LEVEL=info\n');
  write('apps/bot/app.env.bak.20261120', ['GITHUB_APP_ID=123456', pem('RSA ')].join('\n'));
  write('apps/web/.env.bak', 'NODE_ENV=production\n');
  write('apps/web/.env.example', 'API_TOKEN=\n');

  const report = scanPath(root);
  const at = (file: string) => report.findings.filter((f) => f.file === file).map((f) => f.ruleId);

  it('flags extensionless SSH private key files', () => {
    expect(at('deploy/id_rsa')).toEqual(['sensitive-file-committed']);
    expect(at('deploy/id_ed25519')).toEqual(['sensitive-file-committed']);
  });

  it('flags .pem and app.env by name', () => {
    expect(at('certs/server.pem')).toEqual(['sensitive-file-committed']);
    expect(at('apps/bot/app.env')).toEqual(['sensitive-file-committed']);
  });

  it('reads an env backup and reports the key inside it', () => {
    expect(at('apps/bot/app.env.bak.20261120')).toContain('secret-github-app-private-key');
  });

  it('flags an env backup with no recognisable secret by name, as critical', () => {
    const finding = report.findings.find((f) => f.file === 'apps/web/.env.bak')!;
    expect(finding.ruleId).toBe('sensitive-file-committed');
    expect(finding.severity).toBe('critical');
    expect(finding.reference).toMatch(/attack-vectors\//);
  });

  it('leaves templates alone', () => {
    expect(at('apps/web/.env.example')).toEqual([]);
  });

  it('ids helper agrees with scanText for a single file', () => {
    expect(ids('x.env', pem())).toContain('secret-private-key');
  });
});

/**
 * `secret-committed-env-file`: a production `.env` backup committed to a public
 * repository. Its vendor-shaped keys were found one by one, but nothing said
 * "this whole file is a dotenv file full of credentials", and plain passwords
 * like a DataForSEO login match no vendor format at all.
 *
 * Every value is FAKE and assembled at runtime so no secret scanner (GitHub
 * push protection included) reads this file as a leak.
 */
const FAKE_PASSWORD = 'fake' + 'Pass' + '9876';
const FAKE_SECRET = ['FAKE', 'secret', 'value', '1234'].join('');
const FAKE_RESEND = 're_' + 'FAKEab12' + '_' + 'FAKEcd34FAKEef56FAKEgh78';
const FAKE_RESEND_LOOSE = 're_' + 'FAKEab12FAKEcd34FAKEef56FAKEgh78';
const PROD_ENV = [
  '# production, copied 2026-07-28',
  'NODE_ENV=production',
  'APP_URL=https://app.invalid',
  `DATAFORSEO_PASSWORD=${FAKE_PASSWORD}`,
  `SESSION_SECRET="${FAKE_SECRET}"`,
  `RESEND_API_KEY=${FAKE_RESEND}`,
].join('\n');
const envFinding = (path: string, source: string) =>
  scanText(path, source).find((f) => f.ruleId === 'secret-committed-env-file');

describe('dotenv file names', () => {
  it('accepts .env, .env.*, *.env and *.env.*', () => {
    for (const name of [
      '.env',
      '.env.bak-2026-07-28',
      '.env.production',
      '.env.local',
      'app.env',
      'deploy.env.bak-1',
      'prod.env.old',
    ]) {
      expect(isDotenvFileName(name), name).toBe(true);
    }
  });

  it('rejects templates and source files that merely mention env', () => {
    for (const name of [
      '.env.example',
      '.env.sample',
      '.env.template',
      '.env.dist',
      '.env.defaults',
      '.env.schema',
      '.env.example.bak',
      'app.env.sample',
      'vite.env.d.ts',
      'config.env.js',
      'environment.ts',
      'env',
      '.envrc',
    ]) {
      expect(isDotenvFileName(name), name).toBe(false);
    }
  });

  it('treats template values as placeholders', () => {
    for (const value of ['', 'changeme', 'xxxxxxxxxx', 'your-api-key-here', '<token>', '${API_TOKEN}', 'example-secret', 'placeholder', 'TODO set me', 'aaaaaaaaaaaa', 'short']) {
      expect(isDotenvPlaceholder(value), value).toBe(true);
    }
    expect(isDotenvPlaceholder(FAKE_PASSWORD)).toBe(false);
  });
});

describe('secret-committed-env-file', () => {
  it('flags a committed production .env backup once, as critical, on the first secret key', () => {
    const findings = scanText('.env.bak-2026-07-28', PROD_ENV).filter((f) => f.ruleId === 'secret-committed-env-file');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('critical');
    expect(findings[0]!.line).toBe(4);
    expect(findings[0]!.message).toMatch(/3 secret-looking keys/);
    expect(findings[0]!.category).toBe('secret');
    expect(findings[0]!.sensitive).toBe(true);
  });

  it('never prints a value', () => {
    const finding = envFinding('.env.bak-2026-07-28', PROD_ENV)!;
    const text = JSON.stringify(finding);
    for (const value of [FAKE_PASSWORD, FAKE_SECRET, FAKE_RESEND]) expect(text).not.toContain(value);
    expect(finding.excerpt).toBe('DATAFORSEO_PASSWORD=<redacted>');
  });

  it('catches a plain password no vendor rule describes', () => {
    expect(envFinding('deploy/app.env', `DATAFORSEO_PASSWORD=${FAKE_PASSWORD}`)).toBeDefined();
    expect(envFinding('deploy.env.bak-1', `export SMTP_PASS='${FAKE_PASSWORD}'`)).toBeDefined();
  });

  it('stays silent on a committed .env.example full of placeholders', () => {
    const template = [
      'DATAFORSEO_PASSWORD=changeme',
      'SESSION_SECRET=your-session-secret',
      'RESEND_API_KEY=<resend key>',
      'API_TOKEN=${API_TOKEN}',
      `STRIPE_SECRET_KEY=${FAKE_PASSWORD}`,
    ].join('\n');
    expect(scanText('.env.example', template).filter((f) => f.ruleId === 'secret-committed-env-file')).toEqual([]);
    expect(committedEnvFile('.env.example', template.split('\n'))).toBeNull();
  });

  it('stays silent on a real .env whose secret keys are all placeholders or empty', () => {
    const source = ['API_TOKEN=', 'DB_PASSWORD=changeme', 'JWT_SECRET=xxxxxxxx', 'SECRET_KEY="<generate one>"'].join('\n');
    expect(envFinding('.env', source)).toBeUndefined();
  });

  it('ignores public and configuration keys', () => {
    const source = [
      'NEXT_PUBLIC_SUPABASE_ANON_KEY=' + 'FAKEanonFAKEanon',
      'STRIPE_PUBLISHABLE_KEY=' + 'pk_' + 'FAKEFAKEFAKE',
      'NEXTAUTH_URL=https://app.invalid',
      'TOKEN_TTL=86400000',
      'AUTH_PROVIDER=github-oauth',
    ].join('\n');
    expect(envFinding('.env.production', source)).toBeUndefined();
  });

  it('counts a URL with credentials under any name', () => {
    const finding = envFinding('.env', 'DATABASE_URL=postgres://app:' + FAKE_PASSWORD + '@db.invalid/app');
    expect(finding?.message).toMatch(/1 secret-looking key\b/);
  });

  it('honours an inline suppression on the reported line', () => {
    const source = ['# threatcrush-disable-next-line secret-committed-env-file', `SMTP_PASSWORD=${FAKE_PASSWORD}`].join('\n');
    expect(envFinding('.env', source)).toBeUndefined();
  });

  it('is softened, not dropped, under a test path', () => {
    expect(envFinding('test/fixtures/.env', `SMTP_PASSWORD=${FAKE_PASSWORD}`)?.severity).toBe('low');
  });

  it('does not fire on source files', () => {
    expect(envFinding('src/vite.env.d.ts', `API_KEY=${FAKE_PASSWORD}`)).toBeUndefined();
  });
});

describe('secret-resend-key', () => {
  it('matches the issued re_<8>_<24> layout', () => {
    expect(secretIds('.env', `RESEND_API_KEY=${FAKE_RESEND}`)).toContain('secret-resend-key');
    expect(secretIds('src/mail.ts', `const resend = new Resend("${FAKE_RESEND}");`)).toContain('secret-resend-key');
  });

  it('matches a re_ key without the inner underscore', () => {
    expect(looksLikeResendKey(FAKE_RESEND_LOOSE)).toBe(true);
    expect(secretIds('.env', `RESEND_API_KEY=${FAKE_RESEND_LOOSE}`)).toContain('secret-resend-key');
  });

  it('does not match identifiers that start with re_', () => {
    for (const ident of ['re_compile_pattern_cache', 're_split_on_whitespace_regex', 'RE_MATCH_EVERYTHING_PATTERN', 're_compileRegexPatternCache']) {
      expect(secretIds('src/util.py', `${ident} = None`), ident).not.toContain('secret-resend-key');
    }
  });

  it('redacts the key in the excerpt', () => {
    const finding = scanText('src/mail.ts', `const k = "${FAKE_RESEND}";`).find((f) => f.ruleId === 'secret-resend-key')!;
    expect(finding.excerpt).not.toContain(FAKE_RESEND);
  });
});

describe('scanPath: committed dotenv backup', () => {
  const root = mkdtempSync(join(tmpdir(), 'tc-dotenv-'));
  afterAll(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(join(root, '.env.bak-2026-07-28'), PROD_ENV);
  writeFileSync(join(root, '.env.example'), ['DATAFORSEO_PASSWORD=changeme', 'RESEND_API_KEY=re_xxxxxxxx'].join('\n'));
  const report = scanPath(root);
  const at = (file: string) => report.findings.filter((f) => f.file === file).map((f) => f.ruleId);

  it('reports the backup as a committed env file and the Resend key inside it', () => {
    expect(at('.env.bak-2026-07-28')).toEqual(expect.arrayContaining(['secret-committed-env-file', 'secret-resend-key']));
  });

  it('leaves the template alone', () => {
    expect(at('.env.example')).toEqual([]);
  });
});
