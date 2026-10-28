import { afterEach, describe, expect, it, vi } from 'vitest';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fakeCloud, isolateHome, type FakeReply } from '../../daemon/__tests__/helpers/fake-cloud.js';

// Imported after isolateHome(): cli-config fixes ~/.threatcrush at load time.
const home = isolateHome();
const { writeCliConfig } = await import('../../core/cli-config.js');
const { fleetImportCommand, resolveOrg } = await import('../fleet.js');

const orgs = [
  { id: 'org-a', slug: 'acme', name: 'Acme', user_role: 'owner' },
  { id: 'org-b', slug: 'beta', name: 'Beta', user_role: 'member' },
];
const inventory = { devices: [{ id: 'dev2', name: 'dev2', profile: 'server', status: 'active', hostnames: [], addresses: { ipv4: [], ipv6: [] } }] };

function cloud(put: FakeReply) {
  return fakeCloud((req): FakeReply => (req.path === '/api/orgs' ? { status: 200, body: { organizations: orgs } } : put));
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

describe('fleet import', () => {
  it('PUTs the file to the only org you administer', async () => {
    writeCliConfig({ token: 't', refresh_token: 'r' });
    const file = join(home, 'opendevice.json');
    writeFileSync(file, JSON.stringify(inventory));
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const c = cloud({ status: 200, body: { ok: true, warnings: [], cost: { devices: 1, monthly: { USD: 149 }, counted: 1, unstated: [] } } });

    await fleetImportCommand(file);

    const put = c.requests.find((r) => r.method === 'PUT');
    expect(put?.path).toBe('/api/orgs/org-a/inventory');
    expect(put?.auth).toBe('Bearer t');
    expect(process.exitCode).toBeUndefined();
  });

  it('prints the validation errors and exits non-zero on a 422', async () => {
    writeCliConfig({ token: 't', refresh_token: 'r' });
    const file = join(home, 'bad.json');
    writeFileSync(file, JSON.stringify({ devices: [{}] }));
    const errors: string[] = [];
    vi.spyOn(console, 'error').mockImplementation((m: string) => { errors.push(m); });
    cloud({ status: 422, body: { error: 'Invalid OpenDevice inventory', errors: ['devices[0].id is required'], warnings: [] } });

    await fleetImportCommand(file, { org: 'acme' });

    expect(process.exitCode).toBe(1);
    expect(errors.join('\n')).toContain('devices[0].id is required');
  });

  it('refuses a file that is not JSON before calling the API', async () => {
    const file = join(home, 'notjson.json');
    writeFileSync(file, 'nope');
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const c = cloud({ status: 500 });
    await fleetImportCommand(file);
    expect(c.requests).toHaveLength(0);
    expect(process.exitCode).toBe(1);
  });
});

describe('resolveOrg', () => {
  it('takes --org by slug, else the current org', async () => {
    writeCliConfig({ token: 't', refresh_token: 'r', current_org_id: 'org-b' });
    cloud({ status: 200 });
    expect((await resolveOrg('acme'))?.id).toBe('org-a');
    expect((await resolveOrg())?.id).toBe('org-b');
  });
});
