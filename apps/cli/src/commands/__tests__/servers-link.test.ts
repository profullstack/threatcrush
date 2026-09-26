import { afterEach, describe, expect, it, vi } from 'vitest';
import { fakeCloud, isolateHome, type FakeReply } from '../../daemon/__tests__/helpers/fake-cloud.js';

// Imported after isolateHome(): cli-config fixes ~/.threatcrush at load time.
isolateHome();
const { writeCliConfig, readCliConfig } = await import('../../core/cli-config.js');
const { linkServer } = await import('../servers.js');

const orgs = [
  { id: 'org-a', slug: 'acme', name: 'Acme' },
  { id: 'org-b', slug: 'beta', name: 'Beta' },
];

function dashboard(servers: Array<{ id: string; name: string; hostname: string | null }>) {
  return fakeCloud((req): FakeReply => {
    if (req.path === '/api/orgs') return { status: 200, body: { organizations: orgs } };
    if (req.method === 'GET') return { status: 200, body: { servers } };
    return { status: 201, body: { server: { id: 'srv-new', name: req.body?.name, hostname: 'web-1' } } };
  });
}

const neverAsk = () => Promise.reject(new Error('should not prompt'));

afterEach(() => vi.unstubAllGlobals());

describe('servers link', () => {
  it('reuses the server whose hostname matches this machine', async () => {
    writeCliConfig({ token: 't', refresh_token: 'r', current_org_id: 'org-b' });
    const cloud = dashboard([
      { id: 'srv-other', name: 'db', hostname: 'db-1' },
      { id: 'srv-mine', name: 'web', hostname: 'WEB-1' },
    ]);

    const result = await linkServer({ hostname: 'web-1' }, neverAsk);

    expect(result).toMatchObject({ created: false, org: { id: 'org-b' }, server: { id: 'srv-mine' } });
    expect(cloud.requests.some((r) => r.method === 'POST')).toBe(false);
    expect(readCliConfig()).toMatchObject({ server_id: 'srv-mine', server_org_id: 'org-b' });
  });

  it('registers a new server when none matches, in the org named by --org', async () => {
    writeCliConfig({ token: 't', refresh_token: 'r', current_org_id: 'org-b' });
    const cloud = dashboard([{ id: 'srv-other', name: 'db', hostname: 'db-1' }]);

    const result = await linkServer({ org: 'acme', hostname: 'web-1', name: 'Web one' }, neverAsk);

    expect(result).toMatchObject({ created: true, org: { id: 'org-a' }, server: { id: 'srv-new' } });
    const post = cloud.requests.find((r) => r.method === 'POST');
    expect(post?.path).toBe('/api/orgs/org-a/servers');
    expect(post?.body).toEqual({ name: 'Web one', hostname: 'web-1' });
    expect(readCliConfig()).toMatchObject({ server_id: 'srv-new', server_org_id: 'org-a' });
  });

  it('refuses without a session', async () => {
    writeCliConfig({});
    await expect(linkServer({ hostname: 'web-1' }, neverAsk)).rejects.toThrow(/login/);
  });
});
