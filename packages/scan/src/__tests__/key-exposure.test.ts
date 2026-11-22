import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { scanPath } from '../node/walk';
import {
  isEnvBackupName,
  isEnvFileName,
  jwtClaimsRole,
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
    const found = scanText('.env', `SUPABASE_SERVICE_ROLE_KEY=${jwt('service_role')}`).filter((f) => f.category === 'secret');
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
