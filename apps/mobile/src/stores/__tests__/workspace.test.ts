import { beforeEach, describe, expect, it } from 'vitest';
import { useAuthStore } from '../auth';
import { DETECTIONS_PAGE, useWorkspaceStore } from '../workspace';
import { mockHttp } from '../../__tests__/helpers/http';

const ORG_A = { id: 'org-a', name: 'Acme', slug: 'acme', user_role: 'owner', created_at: '2026-01-01' };
const ORG_B = { id: 'org-b', name: 'Beta', slug: 'beta', user_role: 'member', created_at: '2026-02-01' };

const server = (id: string, orgId: string) => ({
  id,
  org_id: orgId,
  name: `srv-${id}`,
  hostname: `${id}.example.com`,
  ip_address: null,
  status: 'offline',
  last_seen: null,
  threatcrushd_version: null,
  created_at: '2026-01-01',
});

const detection = (id: string) => ({
  id,
  server_id: 's1',
  rule_id: 'ssh-brute-force',
  severity: 'high',
  title: `Brute force ${id}`,
  description: null,
  source_ip: '203.0.113.9',
  username: null,
  detected_at: '2026-09-01T00:00:00Z',
  status: 'new',
});

/** Routes for one org's four datasets. */
function orgRoutes(orgId: string, data: { servers?: unknown[]; detections?: unknown[]; total?: number } = {}) {
  return {
    [`GET /api/orgs/${orgId}/servers`]: () => ({ body: { servers: data.servers ?? [] } }),
    [`GET /api/orgs/${orgId}/detections?limit=${DETECTIONS_PAGE}&offset=0`]: () => ({
      body: { detections: data.detections ?? [], total: data.total ?? data.detections?.length ?? 0 },
    }),
    [`GET /api/orgs/${orgId}/remediations?limit=50&offset=0`]: () => ({
      body: { remediations: [{ id: `rem-${orgId}`, server_id: 's1', status: 'pending' }], total: 1 },
    }),
    [`GET /api/orgs/${orgId}/runs?limit=25&offset=0`]: () => ({
      body: { runs: [{ id: `run-${orgId}`, status: 'succeeded' }], total: 7 },
    }),
  };
}

describe('workspace store', () => {
  beforeEach(() => {
    useWorkspaceStore.getState().reset();
    useAuthStore.setState({
      status: 'signedIn',
      session: {
        accessToken: 'access-1',
        refreshToken: 'refresh-1',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        userId: 'user-1',
        email: 'ops@example.com',
      },
    });
  });

  it("opens the org the profile says is current and loads that org's real data", async () => {
    const http = mockHttp({
      'GET /api/orgs': () => ({ body: { organizations: [ORG_A, ORG_B] } }),
      'GET /api/auth/me': () => ({ body: { profile: { current_org_id: 'org-b' } } }),
      ...orgRoutes('org-b', { servers: [server('s1', 'org-b')], detections: [detection('d1')], total: 120 }),
    });

    await useWorkspaceStore.getState().load();

    const s = useWorkspaceStore.getState();
    expect(s.status).toBe('ready');
    expect(s.currentOrgId).toBe('org-b');
    expect(s.servers.map((x) => x.id)).toEqual(['s1']);
    expect(s.detections.map((x) => x.id)).toEqual(['d1']);
    expect(s.detectionsTotal).toBe(120);
    expect(s.remediations.map((x) => x.id)).toEqual(['rem-org-b']);
    expect(s.runs.map((x) => x.id)).toEqual(['run-org-b']);
    expect(s.runsTotal).toBe(7);
    expect(http.requests.every((r) => r.auth === 'Bearer access-1')).toBe(true);
    expect(http.requests.some((r) => r.path.startsWith('/api/orgs/org-a/'))).toBe(false);
  });

  it("falls back to the first org when the profile's current org isn't one of the user's", async () => {
    mockHttp({
      'GET /api/orgs': () => ({ body: { organizations: [ORG_A, ORG_B] } }),
      'GET /api/auth/me': () => ({ body: { profile: { current_org_id: 'org-gone' } } }),
      ...orgRoutes('org-a'),
    });

    await useWorkspaceStore.getState().load();
    expect(useWorkspaceStore.getState().currentOrgId).toBe('org-a');
  });

  it('is empty, not faked, when the user has no organizations', async () => {
    const http = mockHttp({
      'GET /api/orgs': () => ({ body: { organizations: [] } }),
      'GET /api/auth/me': () => ({ body: { profile: { current_org_id: null } } }),
    });

    await useWorkspaceStore.getState().load();

    const s = useWorkspaceStore.getState();
    expect(s.status).toBe('ready');
    expect(s.currentOrgId).toBeNull();
    expect(s.servers).toEqual([]);
    expect(s.detections).toEqual([]);
    expect(s.runs).toEqual([]);
    expect(http.requests.map((r) => r.path).sort()).toEqual(['/api/auth/me', '/api/orgs']);
  });

  it('reports an API failure instead of showing empty data', async () => {
    mockHttp({
      'GET /api/orgs': () => ({ body: { organizations: [ORG_A] } }),
      'GET /api/auth/me': () => ({ body: { profile: {} } }),
      ...orgRoutes('org-a'),
      [`GET /api/orgs/org-a/detections?limit=${DETECTIONS_PAGE}&offset=0`]: () => ({
        status: 500,
        body: { error: 'Failed to fetch detections' },
      }),
    });

    await useWorkspaceStore.getState().load();

    expect(useWorkspaceStore.getState().status).toBe('error');
    expect(useWorkspaceStore.getState().error).toBe('Failed to fetch detections');
  });

  it("switching orgs drops the old org's data, saves the choice, and ignores late replies", async () => {
    const orgA = orgRoutes('org-a', { servers: [server('a1', 'org-a')], detections: [detection('da')] });
    let releaseA!: () => void;
    const http = mockHttp({
      'GET /api/orgs': () => ({ body: { organizations: [ORG_A, ORG_B] } }),
      'GET /api/auth/me': () => ({ body: { profile: { current_org_id: 'org-a' } } }),
      'PATCH /api/auth/me': () => ({ body: { profile: { current_org_id: 'org-b' } } }),
      ...orgA,
      // org-a's servers reply only after the user has already switched away.
      'GET /api/orgs/org-a/servers': () => {
        const { promise, resolve } = Promise.withResolvers<void>();
        releaseA = resolve;
        return promise.then(() => ({ body: { servers: [server('a1', 'org-a')] } }));
      },
      ...orgRoutes('org-b', { servers: [server('b1', 'org-b')] }),
    });

    const loadingA = useWorkspaceStore.getState().load();
    await expect.poll(() => http.requests.some((r) => r.path === '/api/orgs/org-a/servers')).toBe(true);

    await useWorkspaceStore.getState().selectOrg('org-b');
    releaseA();
    await loadingA;

    const s = useWorkspaceStore.getState();
    expect(s.currentOrgId).toBe('org-b');
    expect(s.servers.map((x) => x.id)).toEqual(['b1']);
    expect(s.detections).toEqual([]);
    expect(http.requests).toContainEqual(
      expect.objectContaining({ method: 'PATCH', path: '/api/auth/me', body: { current_org_id: 'org-b' } }),
    );
  });

  it('pages detections by offset and stops at the total', async () => {
    const firstPage = Array.from({ length: DETECTIONS_PAGE }, (_, i) => detection(`d${i}`));
    const http = mockHttp({
      'GET /api/orgs': () => ({ body: { organizations: [ORG_A] } }),
      'GET /api/auth/me': () => ({ body: { profile: {} } }),
      ...orgRoutes('org-a', { servers: [server('s1', 'org-a')], detections: firstPage, total: 52 }),
      [`GET /api/orgs/org-a/detections?limit=${DETECTIONS_PAGE}&offset=${DETECTIONS_PAGE}`]: () => ({
        body: { detections: [detection('d50'), detection('d51')], total: 52 },
      }),
    });
    await useWorkspaceStore.getState().load();

    await useWorkspaceStore.getState().loadMoreDetections();
    expect(useWorkspaceStore.getState().detections).toHaveLength(52);

    const before = http.requests.length;
    await useWorkspaceStore.getState().loadMoreDetections();
    expect(http.requests.length).toBe(before);
  });
});
