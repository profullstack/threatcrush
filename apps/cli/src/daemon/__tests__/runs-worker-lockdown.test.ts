import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fakeCloud, isolateHome } from './helpers/fake-cloud.js';

isolateHome();
const { writeCliConfig } = await import('../../core/cli-config.js');
const { RunsWorker, isPublicTarget, pentestTargetError, scanTargetError } = await import('../workers/runs-worker.js');

const bus = { publish: () => {}, on: () => {}, announceModule: () => {} } as never;

describe('dashboard scan targets', () => {
  const root = mkdtempSync(join(tmpdir(), 'tc-runs-'));
  afterAll(() => rmSync(root, { recursive: true, force: true }));
  const allowed = join(root, 'app');
  const secret = join(root, 'secret');
  mkdirSync(allowed);
  mkdirSync(secret);
  symlinkSync(secret, join(allowed, 'escape'));

  it('refuses every scan until the operator lists directories', () => {
    expect(scanTargetError('/', [])).toMatch(/run_scan_paths/);
    expect(scanTargetError(allowed, [])).toMatch(/run_scan_paths/);
  });

  it('allows only paths under a listed directory, symlinks resolved', () => {
    expect(scanTargetError(allowed, [allowed])).toBeNull();
    expect(scanTargetError('/root/.ssh', [allowed])).not.toBeNull();
    expect(scanTargetError(secret, [allowed])).toMatch(/outside/);
    expect(scanTargetError(join(allowed, 'escape'), [allowed])).toMatch(/outside/);
    expect(scanTargetError(`${allowed}/../secret`, [allowed])).toMatch(/outside/);
    expect(scanTargetError(`${allowed}-other`, [allowed])).not.toBeNull();
  });
});

describe('dashboard pentest targets', () => {
  it('never reaches loopback, private ranges or cloud metadata', async () => {
    for (const url of ['http://127.0.0.1:5432', 'http://169.254.169.254/latest/meta-data', 'https://10.0.0.5', 'http://[::1]:8080', 'http://[::ffff:127.0.0.1]', 'http://0.0.0.0', 'http://100.64.1.1']) {
      expect(await pentestTargetError(url)).toMatch(/not a public address/);
    }
    expect(await pentestTargetError('file:///etc/passwd', async () => [])).not.toBeNull();
    expect(await pentestTargetError('httpx://127.0.0.1')).toMatch(/http/);
  });

  it('checks what a name resolves to', async () => {
    expect(await pentestTargetError('https://internal.example', async () => ['10.1.2.3'])).toMatch(/10\.1\.2\.3/);
    expect(await pentestTargetError('https://mixed.example', async () => ['93.184.216.34', '127.0.0.1'])).toMatch(/127\.0\.0\.1/);
    expect(await pentestTargetError('example.com', async () => ['93.184.216.34'])).toBeNull();
    expect(isPublicTarget('8.8.8.8')).toBe(true);
  });
});

describe('RunsWorker', () => {
  beforeEach(() => {
    writeCliConfig({ token: 'tok', refresh_token: 'r1', server_id: 'srv-1', server_org_id: 'org-linked' });
  });
  afterEach(() => vi.unstubAllGlobals());

  it('is off unless the operator opts in, and then asks the cloud for nothing', async () => {
    const calls: string[] = [];
    fakeCloud(({ path: url }) => { calls.push(url); return { status: 200, body: { organizations: [{ id: 'org-attacker' }] } }; });
    const logs: string[] = [];
    const worker = new RunsWorker(bus, { enabled: false, scanRoots: [], log: (l) => logs.push(l) });
    await worker.start();
    worker.stop();
    expect(calls).toHaveLength(0);
    expect(logs.join('\n')).toMatch(/runs off/);
  });

  it('only claims runs for the linked org, never every org its user is in', async () => {
    const calls: string[] = [];
    fakeCloud(({ path: url }) => {
      calls.push(url);
      if (url.endsWith('/api/orgs')) return { status: 200, body: { organizations: [{ id: 'org-attacker' }, { id: 'org-linked' }] } };
      return { status: 200, body: { run: null } };
    });
    const worker = new RunsWorker(bus, { enabled: true, scanRoots: [] });
    await worker.start();
    await new Promise((r) => setTimeout(r, 20));
    worker.stop();
    expect(calls.some((u) => u.includes('org-attacker'))).toBe(false);
    expect(calls.some((u) => u.includes('/api/orgs/org-linked/runs/pending'))).toBe(true);
  });

  it('refuses a queued scan of / instead of running it', async () => {
    const worker = new RunsWorker(bus, { enabled: true, scanRoots: [] });
    const result = await worker.execute({
      id: 'r1', org_id: 'org-linked', property_id: 'p1', type: 'scan',
      property: { id: 'p1', name: 'x', kind: 'repo', target: '/' },
    });
    expect(result.error).toMatch(/run_scan_paths/);
    expect(result.findings).toHaveLength(0);
  });
});
