import { describe, expect, it } from 'vitest';
import {
  classifyPrivateKey, classifySecretFile, envSecretNames, exposedTo, isCandidate, isPasswordExportHeader, looksLikeFixture, parseGroupFile, secretItem,
} from '../host-scan/secrets.js';

// Fixtures are built at runtime from obviously fake material so that no file in
// this repository looks like a real key or token to a secret scanner.
const B = '-----BEGIN ';
const E = '-----END ';
const PK = 'PRIVATE KEY-----';

function pem(kind: string, body: string, headers = ''): string {
  return `${B}${kind}${kind ? ' ' : ''}${PK}\n${headers}${body}\n${E}${kind}${kind ? ' ' : ''}${PK}\n`;
}

function opensshKey(cipher: string): string {
  const magic = Buffer.from('openssh-key-v1\0', 'latin1');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(cipher.length);
  const rest = Buffer.from('fake-fixture-not-a-key'.repeat(4), 'latin1');
  const b64 = Buffer.concat([magic, len, Buffer.from(cipher, 'latin1'), rest]).toString('base64').replace(/(.{70})/g, '$1\n');
  return pem('OPENSSH', b64);
}

const FAKE_BODY = 'RklYVFVSRS1OT1QtQS1LRVk=';

describe('private key detection', () => {
  it('reads the OpenSSH cipher field', () => {
    expect(classifyPrivateKey(opensshKey('none'))).toEqual({ kind: 'OPENSSH', encrypted: false });
    expect(classifyPrivateKey(opensshKey('aes256-ctr'))).toEqual({ kind: 'OPENSSH', encrypted: true });
  });

  it('handles PKCS#1, SEC1, PKCS#8 and their encrypted forms', () => {
    expect(classifyPrivateKey(pem('RSA', FAKE_BODY))).toEqual({ kind: 'RSA', encrypted: false });
    expect(classifyPrivateKey(pem('RSA', FAKE_BODY, 'Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n'))).toEqual({ kind: 'RSA', encrypted: true });
    expect(classifyPrivateKey(pem('EC', FAKE_BODY))).toEqual({ kind: 'EC', encrypted: false });
    expect(classifyPrivateKey(pem('', FAKE_BODY))).toEqual({ kind: 'PKCS8', encrypted: false });
    expect(classifyPrivateKey(pem('ENCRYPTED', FAKE_BODY))).toEqual({ kind: 'PKCS8', encrypted: true });
    expect(classifyPrivateKey(`${B}CERTIFICATE-----\n${FAKE_BODY}\n${E}CERTIFICATE-----\n`)).toBeNull();
  });

  it('reports only unencrypted keys', () => {
    expect(classifySecretFile('.ssh/id_ed25519', 'id_ed25519', opensshKey('none'))).toMatchObject({ type: 'private-key', label: 'unencrypted OPENSSH private key' });
    expect(classifySecretFile('.ssh/id_ed25519', 'id_ed25519', opensshKey('aes256-ctr'))).toBeNull();
    expect(classifySecretFile('apps/bot/github-app.pem', 'github-app.pem', pem('RSA', FAKE_BODY))).toMatchObject({ type: 'private-key' });
  });
});

describe('token and credential files', () => {
  it('gh CLI hosts.yml', () => {
    expect(classifySecretFile('.config/gh/hosts.yml', 'hosts.yml', 'github.com:\n    user: someone\n    oauth_token: FIXTURE\n    git_protocol: https\n'))
      .toMatchObject({ type: 'gh-token', count: 1 });
    // Keyring-backed gh has no token in the file.
    expect(classifySecretFile('.config/gh/hosts.yml', 'hosts.yml', 'github.com:\n    user: someone\n    git_protocol: https\n')).toBeNull();
  });

  it('npmrc, pypirc, git-credentials, netrc', () => {
    expect(classifySecretFile('.npmrc', '.npmrc', '//registry.npmjs.org/:_authToken=FIXTURE\n')).toMatchObject({ type: 'npm-token', count: 1 });
    expect(classifySecretFile('.npmrc', '.npmrc', '# //registry.npmjs.org/:_authToken=FIXTURE\nsave-exact=true\n')).toBeNull();
    expect(classifySecretFile('.pypirc', '.pypirc', '[pypi]\nusername = __token__\npassword = FIXTURE\n')).toMatchObject({ type: 'pypi-password' });
    expect(classifySecretFile('.git-credentials', '.git-credentials', 'https://user:FIXTURE@example.com\n')).toMatchObject({ type: 'git-credentials', count: 1 });
    expect(classifySecretFile('.netrc', '.netrc', 'machine example.com login me password FIXTURE\n')).toMatchObject({ type: 'netrc' });
  });

  it('docker config counts registries with stored auth, ignores credsStore', () => {
    const cfg = JSON.stringify({ auths: { 'ghcr.io': { auth: 'RklYVFVSRQ==' }, 'registry.example.com': {} }, credsStore: 'pass' });
    expect(classifySecretFile('.docker/config.json', 'config.json', cfg)).toMatchObject({ type: 'docker-auth', count: 1, label: expect.stringContaining('ghcr.io') });
    expect(classifySecretFile('.docker/config.json', 'config.json', JSON.stringify({ credsStore: 'pass' }))).toBeNull();
  });

  it('cloud credentials', () => {
    expect(classifySecretFile('.aws/credentials', 'credentials', '[default]\naws_access_key_id = FIXTURE\naws_secret_access_key = FIXTURE\n')).toMatchObject({ type: 'aws-credentials' });
    expect(classifySecretFile('.kube/config', 'config', 'users:\n- name: x\n  user:\n    token: FIXTURE\n')).toMatchObject({ type: 'kubeconfig' });
    expect(classifySecretFile('.config/gcloud/application_default_credentials.json', 'application_default_credentials.json', '{}')).toMatchObject({ type: 'gcloud-credentials' });
  });

  it('JSON identity / service-account files', () => {
    expect(classifySecretFile('.config/vault/identity.json', 'identity.json', `{"id":"x","privateKey":"${'fx'.repeat(16)}"}`)).toMatchObject({ type: 'json-secret' });
    expect(classifySecretFile('keys/sa.json', 'sa.json', '{"type": "service_account", "private_key": "FIXTURE"}')).toMatchObject({ type: 'json-secret', label: expect.stringContaining('service-account') });
    expect(classifySecretFile('.config/app/settings.json', 'settings.json', '{"theme":"dark","token":"short"}')).toBeNull();
    // Env-var names and templates are not secrets.
    expect(classifySecretFile('.config/app/users.json', 'users.json', '{"token":"TURSO_AUTH_TOKEN_PROD","apiKey":"${API_KEY_FROM_ENVIRONMENT}"}')).toBeNull();
  });
});

describe('.env files', () => {
  it('counts secret-looking names, never values, and skips placeholders and public vars', () => {
    const env = [
      'SUPABASE_SERVICE_ROLE_KEY=fixture-value-1',
      'export STRIPE_SECRET="fixture-value-2"',
      'DATABASE_URL=postgres://app:fixturepw@db:5432/app',
      'NEXT_PUBLIC_SUPABASE_ANON_KEY=fixture-public',
      'API_TOKEN=',
      'ADMIN_PASSWORD=changeme',
      'JWT_SECRET=${JWT_SECRET}',
      'PORT=3000',
      '# OLD_SECRET=commented',
    ].join('\n');
    expect(envSecretNames(env)).toEqual(['SUPABASE_SERVICE_ROLE_KEY', 'STRIPE_SECRET', 'DATABASE_URL']);
    const f = classifySecretFile('src/app/app.env', 'app.env', env);
    expect(f).toMatchObject({ type: 'env-secrets', count: 3 });
    expect(JSON.stringify(f)).not.toContain('fixture-value');
  });

  it('only opens real env files', () => {
    expect(isCandidate('www/site/.env', '.env')).toBe(true);
    expect(isCandidate('www/site/.env.production', '.env.production')).toBe(true);
    expect(isCandidate('app.env', 'app.env')).toBe(true);
    expect(isCandidate('www/site/.env.example', '.env.example')).toBe(false);
    expect(isCandidate('src/index.ts', 'index.ts')).toBe(false);
    expect(isCandidate('.ssh/id_rsa.pub', 'id_rsa.pub')).toBe(false);
    expect(isCandidate('.ssh/known_hosts', 'known_hosts')).toBe(false);
    expect(isCandidate('.ssh/deploy_key', 'deploy_key')).toBe(true);
  });
});

describe('password exports', () => {
  it('recognises manager export headers', () => {
    expect(isPasswordExportHeader('folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp')).toBe(true);
    expect(isPasswordExportHeader('url,username,password,totp,extra,name,grouping,fav')).toBe(true);
    expect(isPasswordExportHeader('"Title","Website","Username","Password","Notes"')).toBe(true);
    expect(isPasswordExportHeader('date,amount,description')).toBe(false);
  });

  it('classifies CSV and JSON exports, skipping encrypted Bitwarden exports', () => {
    expect(classifySecretFile('Downloads/export.csv', 'export.csv', 'name,url,username,password\nx,https://example.com,me,FIXTURE\n')).toMatchObject({ type: 'password-export' });
    expect(classifySecretFile('Downloads/bitwarden_export_20261120.json', 'bitwarden_export_20261120.json', '{"encrypted": false, "items": [{"login": {"username": "me", "password": "FIXTURE"}}]}')).toMatchObject({ type: 'password-export' });
    expect(classifySecretFile('Downloads/bitwarden_export_20261120.json', 'bitwarden_export_20261120.json', '{"encrypted": true, "data": "x"}')).toBeNull();
    // A JSON file merely named *export* is not a password export.
    expect(classifySecretFile('test/exports/node-exports.json', 'node-exports.json', '{"crypto": {"password": "x"}}')).toBeNull();
  });
});

describe('permissions and severity', () => {
  const groups = parseGroupFile('anthony:x:1000:\nstaff:x:50:anthony,bob\nssl-cert:x:110:postgres\n');

  it('world-read always counts; group-read only for shared groups', () => {
    expect(exposedTo(0o644, 'anthony', 1000, groups, ['anthony'])).toBe('world');
    expect(exposedTo(0o640, 'anthony', 1000, groups, ['anthony'])).toBeNull();
    expect(exposedTo(0o640, 'anthony', 50, groups)).toBe('group');
    expect(exposedTo(0o600, 'anthony', 50, groups)).toBeNull();
  });

  it('readable-by-others secrets fail, the rest warn, values never appear', () => {
    const base = { path: '/home/a/.npmrc', type: 'npm-token' as const, label: 'npm registry token', owner: 'a', mode: '644', size: 60, age_days: 3, exposed: 'world' as const };
    expect(secretItem(base).status).toBe('fail');
    expect(secretItem(base, false)).toMatchObject({ status: 'warn', message: expect.stringContaining('parent directory is closed') });
    expect(secretItem({ ...base, exposed: null, mode: '600' })).toMatchObject({ status: 'warn', message: 'npm registry token (owner a, mode 600, 60 B, 3d old)' });
    expect(secretItem({ ...base, type: 'git-history-key', label: 'private key in git history', exposed: null }).status).toBe('fail');
    // Test fixtures are listed but never fail.
    expect(secretItem({ ...base, fixture: true })).toMatchObject({ status: 'warn', message: expect.stringContaining('[test fixture path]') });
    expect(looksLikeFixture('/home/a/src/lib/test/fixtures/key.pem')).toBe(true);
    expect(looksLikeFixture('/home/a/www/site/certs/privkey.pem')).toBe(false);
  });
});
