import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  DEPLOY_RULES,
  evaluateDeployRules,
  isDangerousHostPath,
  parseAuthorizedKeyLines,
  suspiciousKeyComment,
  volumeSource,
} from '../deploy-rules';
import { ATTACK_VECTOR_SLUGS, ATTACK_VECTORS_BASE } from '../references';
import { scanText } from '../text';

/**
 * Deploy-path rules, each against the vulnerable shape and the corrected one
 * beside it. Hosts, users and keys here are placeholders; key blobs are FAKE
 * and split so no scanner reads them as material.
 */
const rules = (path: string, source: string) => scanText(path, source).filter((f) => f.category === 'code');
const ruleIds = (path: string, source: string) => rules(path, source).map((f) => f.ruleId);

const REPO_ROOT = join(__dirname, '..', '..', '..', '..');

describe('every deploy rule is documented', () => {
  it('links to an attack-vectors entry that exists', () => {
    for (const rule of DEPLOY_RULES) {
      expect(rule.reference.startsWith(ATTACK_VECTORS_BASE), rule.id).toBe(true);
      const file = rule.reference.slice(ATTACK_VECTORS_BASE.length);
      expect(existsSync(join(REPO_ROOT, 'attack-vectors', file)), `${rule.id} -> ${file}`).toBe(true);
    }
    for (const slug of ATTACK_VECTOR_SLUGS) {
      expect(existsSync(join(REPO_ROOT, 'attack-vectors', `${slug}.md`)), slug).toBe(true);
    }
  });

  it('is listed by id in the collection README', () => {
    const readme = readFileSync(join(REPO_ROOT, 'attack-vectors', 'README.md'), 'utf-8');
    for (const rule of DEPLOY_RULES) expect(readme, rule.id).toContain(`\`${rule.id}\``);
  });
});

describe('compose files', () => {
  const EXPLOIT = [
    'services:',
    '  app:',
    '    build: .',
    '    user: "0:0"',
    '    volumes:',
    '      - /:/host:ro',
    '      - ~/.ssh:/x:rw',
    '      - /var/run/docker.sock:/var/run/docker.sock',
    '    privileged: true',
    '    cap_add: [SYS_ADMIN]',
  ].join('\n');

  it('finds every escalation in the incident compose file', () => {
    const found = rules('deploy/compose.yml', EXPLOIT);
    const byId = (id: string) => found.filter((f) => f.ruleId === id).map((f) => f.line);
    expect(byId('compose-root-user')).toEqual([4]);
    expect(byId('compose-host-root-mount')).toEqual([6, 7]);
    expect(byId('compose-docker-socket')).toEqual([8]);
    expect(byId('compose-privileged')).toEqual([9, 10]);
    const root = found.find((f) => f.ruleId === 'compose-host-root-mount')!;
    expect(root.severity).toBe('critical');
    expect(root.message).toContain('read-only, and the service runs as root');
    expect(root.reference).toMatch(/ci-forced-command-compose\.md$/);
  });

  it('reads long-syntax bind mounts', () => {
    const source = [
      'services:',
      '  app:',
      '    image: example/app:1.2.3',
      '    volumes:',
      '      - type: bind',
      '        source: /home/deploy/.ssh',
      '        target: /keys',
      '      - type: volume',
      '        source: data',
      '        target: /data',
    ].join('\n');
    expect(ruleIds('docker-compose.prod.yaml', source)).toEqual(['compose-host-root-mount']);
  });

  it('stays silent on a hardened service', () => {
    const source = [
      'services:',
      '  app:',
      '    image: example/app:1.2.3',
      '    user: "1000:1000"',
      '    read_only: true',
      '    volumes:',
      '      - ./data:/data',
      '      - app-cache:/cache',
      '      - /srv/app/uploads:/uploads:ro',
      '    cap_drop: [ALL]',
      'volumes:',
      '  app-cache: {}',
    ].join('\n');
    expect(ruleIds('compose.yml', source)).toEqual([]);
  });

  it('only treats compose-named YAML as compose', () => {
    expect(ruleIds('k8s/values.yml', EXPLOIT)).toEqual([]);
  });

  it('classifies host paths', () => {
    for (const p of ['/', '/root', '/root/.ssh', '/etc', '~/.ssh', '$HOME/.ssh', '${HOME}', '/home', '/home/deploy', '/home/deploy/.ssh/']) {
      expect(isDangerousHostPath(p), p).toBe(true);
    }
    for (const p of ['./data', '/srv/app', '/home/deploy/app/data', '/var/lib/app', 'data']) {
      expect(isDangerousHostPath(p), p).toBe(false);
    }
    expect(volumeSource('${DATA_DIR:-/srv/data}:/data')).toBe('${DATA_DIR:-/srv/data}');
    expect(volumeSource('C:\\data:/data')).toBe('C:\\data');
    expect(volumeSource('/data')).toBeNull();
  });
});

describe('docker compose from a synced repository', () => {
  it('flags rsync to a host then compose -f on the synced path', () => {
    const source = [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      'rsync -az --delete ./ deploy@build-host:/srv/builds/app/',
      'ssh deploy@build-host "docker compose -f /srv/builds/app/compose.yml up -d --build"',
    ].join('\n');
    const found = rules('scripts/deploy.sh', source);
    expect(found.map((f) => f.ruleId)).toEqual(['deploy-compose-from-synced-repo']);
    expect(found[0]!.line).toBe(4);
    expect(found[0]!.severity).toBe('high');
    expect(found[0]!.message).toContain('builds from it');
  });

  it('follows cd and relative compose files inside the ssh command', () => {
    const source = [
      'rsync -az ./ deploy@host:/srv/app',
      "ssh deploy@host 'cd /srv/app && docker compose -f compose.prod.yml up -d'",
    ].join('\n');
    expect(ruleIds('deploy.sh', source)).toEqual(['deploy-compose-from-synced-repo']);
  });

  it('follows an ssh heredoc and a git pull on the host', () => {
    const source = [
      "ssh deploy@host <<'EOF'",
      '  cd /srv/app',
      '  git pull --ff-only',
      '  docker compose up -d --build',
      'EOF',
    ].join('\n');
    const found = rules('deploy.sh', source);
    expect(found.map((f) => f.ruleId)).toEqual(['deploy-compose-from-synced-repo']);
    expect(found[0]!.line).toBe(4);
  });

  it('flags a forced-command allowlist that accepts rsync and runs compose from the build dir', () => {
    const source = [
      '#!/bin/sh',
      'case "$SSH_ORIGINAL_COMMAND" in',
      '  rsync\\ --server*\\ /srv/builds/*) exec $SSH_ORIGINAL_COMMAND ;;',
      '  "docker compose -f /srv/builds/app/compose.yml up -d --build") docker compose -f /srv/builds/app/compose.yml up -d --build ;;',
      '  *) echo denied; exit 1 ;;',
      'esac',
    ].join('\n');
    const found = rules('ops/ci-allow', source);
    expect(found.map((f) => f.ruleId)).toContain('deploy-compose-from-synced-repo');
  });

  it('flags the same chain in a workflow run: block', () => {
    const source = [
      'on: { push: { branches: [main] } }',
      'jobs:',
      '  deploy:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '      - run: rsync -az ./ ci@build-host:/srv/builds/app/',
      '      - run: |',
      '          ssh ci@build-host "docker compose -f /srv/builds/app/compose.yml up -d --build"',
    ].join('\n');
    const found = rules('.github/workflows/deploy.yml', source).filter((f) => f.ruleId === 'deploy-compose-from-synced-repo');
    expect(found.map((f) => f.line)).toEqual([9]);
  });

  it('stays silent when the host runs its own compose file and pulls a pinned image', () => {
    const source = [
      'rsync -az ./dist/ deploy@host:/srv/app/static/',
      'ssh deploy@host "docker compose -f /etc/app/compose.yml pull && docker compose -f /etc/app/compose.yml up -d"',
    ].join('\n');
    expect(ruleIds('deploy.sh', source)).toEqual([]);
  });

  it('stays silent on local compose use with no upload', () => {
    expect(ruleIds('dev.sh', 'docker compose -f compose.dev.yml up --build')).toEqual([]);
  });
});

describe('uploaded scripts run on a host', () => {
  it('flags scp of a script then ssh running it', () => {
    const source = [
      'scp deploy.sh deploy@host:/srv/app/',
      'ssh deploy@host "bash /srv/app/deploy.sh"',
    ].join('\n');
    const found = rules('scripts/release.sh', source);
    expect(found.map((f) => f.ruleId)).toEqual(['deploy-remote-exec-uploaded-script']);
    expect(found[0]!.line).toBe(2);
  });

  it('flags ./script after cd into the upload dir', () => {
    const source = ['rsync -az ./ deploy@host:/srv/app', 'ssh deploy@host "cd /srv/app && ./deploy.sh"'].join('\n');
    expect(ruleIds('release.sh', source)).toEqual(['deploy-remote-exec-uploaded-script']);
  });

  it('flags a repository script piped into a remote shell', () => {
    expect(ruleIds('release.sh', 'ssh deploy@host bash -s < scripts/deploy.sh')).toEqual(['deploy-remote-exec-uploaded-script']);
  });

  it('flags appleboy scp-action + ssh-action in a workflow', () => {
    const source = [
      'on: push',
      'jobs:',
      '  deploy:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: appleboy/scp-action@v0.1.7',
      '        with:',
      '          source: "deploy.sh"',
      '          target: /srv/app',
      '      - uses: appleboy/ssh-action@v1.0.3',
      '        with:',
      '          script: |',
      '            cd /srv/app',
      '            bash deploy.sh',
    ].join('\n');
    const found = rules('.github/workflows/deploy.yml', source).filter((f) => f.ruleId === 'deploy-remote-exec-uploaded-script');
    expect(found.map((f) => f.line)).toEqual([14]);
  });

  it('stays silent on a forced command that only receives data', () => {
    const source = ['scp build.tar.gz deploy@host:/srv/incoming/', "ssh deploy@host 'sudo /usr/local/bin/deploy-release'"].join('\n');
    expect(ruleIds('release.sh', source)).toEqual([]);
  });
});

describe('GitHub App setup callback IDOR', () => {
  const VULNERABLE = [
    "import { NextResponse } from 'next/server';",
    '',
    'export async function GET(req: Request) {',
    '  const url = new URL(req.url);',
    "  const installationId = url.searchParams.get('installation_id');",
    '  const user = await requireUser();',
    '  const inst = await appOctokit.request("GET /app/installations/{id}", { id: installationId });',
    "  await db.from('github_installations').upsert({ user_id: user.id, installation_id: installationId });",
    "  return NextResponse.redirect('/settings');",
    '}',
  ].join('\n');

  it('flags a callback that persists a query-string installation_id with only an App-JWT lookup', () => {
    const found = rules('app/api/github/setup/route.ts', VULNERABLE).filter((f) => f.ruleId === 'github-app-installation-idor');
    expect(found.map((f) => f.line)).toEqual([5]);
    expect(found[0]!.severity).toBe('high');
    expect(found[0]!.reference).toMatch(/github-app-installation-idor\.md$/);
  });

  it('stays silent when the handler checks GET /user/installations', () => {
    const fixed = VULNERABLE.replace(
      '  const inst =',
      '  const mine = await userOctokit.request("GET /user/installations");\n  if (!mine.data.installations.some((i) => String(i.id) === installationId)) return new Response("forbidden", { status: 403 });\n  const inst =',
    );
    expect(ruleIds('app/api/github/setup/route.ts', fixed)).not.toContain('github-app-installation-idor');
  });

  it('stays silent when a verifying helper in the same file is called', () => {
    const fixed = [
      'async function userOwnsInstallation(token: string, id: string) {',
      '  const r = await fetch("https://api.github.com/user/installations", { headers: { authorization: `Bearer ${token}` } });',
      '  return (await r.json()).installations.some((i: { id: number }) => String(i.id) === id);',
      '}',
      '',
      VULNERABLE.replace('  const inst =', '  if (!(await userOwnsInstallation(token, installationId!))) throw new Error("no");\n  const inst ='),
    ].join('\n');
    expect(ruleIds('route.ts', fixed)).not.toContain('github-app-installation-idor');
  });

  it('flags Express and Flask shapes, and ignores handlers that only read', () => {
    const express = [
      "router.get('/github/callback', async (req, res) => {",
      '  const id = req.query.installation_id;',
      '  await Installation.create({ userId: req.user.id, installationId: id });',
      '  res.redirect("/");',
      '});',
    ].join('\n');
    expect(ruleIds('routes/github.js', express)).toContain('github-app-installation-idor');

    const flask = [
      "@app.route('/github/setup')",
      'def setup():',
      "    inst = request.args.get('installation_id')",
      '    db.execute("INSERT INTO installs (user_id, installation_id) VALUES (?, ?)", (current_user.id, inst))',
      '    return redirect("/")',
    ].join('\n');
    expect(ruleIds('app/views.py', flask)).toContain('github-app-installation-idor');

    const readOnly = [
      'export async function GET(req: Request) {',
      "  const id = new URL(req.url).searchParams.get('installation_id');",
      '  return Response.json({ id });',
      '}',
    ].join('\n');
    expect(ruleIds('route.ts', readOnly)).not.toContain('github-app-installation-idor');
  });
});

describe('authorized_keys files', () => {
  const blob = ['AAAAC3NzaC1lZDI1NTE5AAAA', 'IFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE'].join('');
  const key = (prefix: string, comment: string) => [prefix, 'ssh-ed25519', blob, comment].filter(Boolean).join(' ');

  it('flags an unrestricted, dated "ci-diag" key', () => {
    const found = rules('root/.ssh/authorized_keys', key('', 'ci-diag-20261120'));
    expect(found.map((f) => f.ruleId).sort()).toEqual(['authorized-keys-suspicious-comment', 'authorized-keys-unrestricted']);
    expect(found.find((f) => f.ruleId === 'authorized-keys-suspicious-comment')!.severity).toBe('high');
  });

  it('accepts a restricted deploy key and a named personal key', () => {
    const source = [
      key('restrict,from="192.0.2.0/24",command="/usr/local/bin/deploy"', 'deploy@ci'),
      key('restrict', 'alice@laptop'),
    ].join('\n');
    expect(ruleIds('home/deploy/.ssh/authorized_keys', source)).toEqual([]);
  });

  it('flags an sftp-only key, which still reads the whole filesystem', () => {
    const found = ruleIds('authorized_keys', key('restrict,command="internal-sftp"', 'uploader'));
    expect(found).toEqual(['authorized-keys-sftp-unjailed']);
  });

  it('parses options with quoted commas', () => {
    const [parsed] = parseAuthorizedKeyLines(key('from="10.0.0.1,10.0.0.2",command="echo a, b"', 'x'));
    expect(parsed!.options.get('from')).toBe('10.0.0.1,10.0.0.2');
    expect(parsed!.options.get('command')).toBe('echo a, b');
    expect(parsed!.comment).toBe('x');
  });

  it('knows a persistence-style comment from a normal one', () => {
    for (const c of ['ci-diag-20261120', 'ops-recovery-20261027', 'tmp_2026-11-01', 'debug20261120', 'temp-key-20261120']) {
      expect(suspiciousKeyComment(c), c).toBe(true);
    }
    for (const c of ['alice@laptop', 'deploy@ci-20261120', 'github-actions-deploy', 'ci-deploy', 'backup-2026', '']) {
      expect(suspiciousKeyComment(c), c).toBe(false);
    }
  });
});

describe('sshd_config sftp jails', () => {
  it('flags ForceCommand internal-sftp with no ChrootDirectory', () => {
    const source = ['PermitRootLogin no', 'Match User deploy', '  ForceCommand internal-sftp', '  AllowTcpForwarding no'].join('\n');
    const found = rules('etc/ssh/sshd_config', source);
    expect(found.map((f) => [f.ruleId, f.line])).toEqual([['sshd-sftp-without-chroot', 3]]);
  });

  it('accepts a chrooted sftp block', () => {
    const source = ['Match User deploy', '  ChrootDirectory /srv/sftp/%u', '  ForceCommand internal-sftp -d /upload'].join('\n');
    expect(ruleIds('etc/ssh/sshd_config.d/10-deploy.conf', source)).toEqual([]);
  });
});

describe('evaluateDeployRules never throws', () => {
  it('survives malformed YAML and binary-ish text', () => {
    expect(() => evaluateDeployRules('compose.yml', 'services: [\n  - : :', 'config')).not.toThrow();
    expect(() => evaluateDeployRules('x.sh', '\u0000\u0001 ssh "', 'shell')).not.toThrow();
  });
});
