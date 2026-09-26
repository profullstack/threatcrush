import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const ORG = { id: 'org-1', slug: 'acme', name: 'Acme' };

const detection = (id, severity, title = `Detection ${id}`) => ({
  id,
  severity,
  title,
  status: 'new',
  detected_at: '2026-09-25T12:00:00Z',
});

let store;
let api;

function fakeChrome() {
  store = {};
  return {
    storage: {
      local: {
        get: vi.fn(async (key) => (key in store ? { [key]: store[key] } : {})),
        set: vi.fn(async (items) => Object.assign(store, items)),
        remove: vi.fn(async (key) => {
          delete store[key];
        }),
      },
    },
    notifications: { create: vi.fn(async () => 'id'), onClicked: { addListener: vi.fn() }, clear: vi.fn() },
    action: { setTitle: vi.fn(async () => {}), setBadgeText: vi.fn(async () => {}) },
    tabs: { create: vi.fn() },
    runtime: { getURL: (path) => `chrome-extension://test/${path}` },
  };
}

/** Load the module with the API returning `pages` in order, one per poll. */
async function load({ token = 'jwt', organizations = [ORG], pages = [] } = {}) {
  const queue = [...pages];
  api = {
    getAuthToken: vi.fn(async () => token),
    getProfile: vi.fn(async () => ({ profile: { current_org_id: null } })),
    listOrganizations: vi.fn(async () => ({ organizations })),
    listDetections: vi.fn(async () => {
      const next = queue.shift();
      if (next instanceof Error) throw next;
      return next;
    }),
  };
  vi.doMock('../src/lib/api.js', () => api);
  return import('../src/background/detections.js');
}

beforeEach(() => {
  vi.resetModules();
  global.chrome = fakeChrome();
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  vi.doUnmock('../src/lib/api.js');
  vi.restoreAllMocks();
});

describe('checkDetections', () => {
  it('counts new detections without notifying for those that existed at the first poll', async () => {
    const { checkDetections } = await load({
      pages: [{ detections: [detection('a', 'critical'), detection('b', 'low')], total: 2 }],
    });

    const result = await checkDetections();

    expect(result).toMatchObject({ signedIn: true, org: ORG, newCount: 2, urgentCount: 1 });
    expect(api.listDetections).toHaveBeenCalledWith('org-1', expect.objectContaining({ status: 'new' }));
    expect(chrome.notifications.create).not.toHaveBeenCalled();
  });

  it('notifies only for high/critical detections that appeared since the previous poll', async () => {
    const { checkDetections } = await load({
      pages: [
        { detections: [detection('a', 'critical')], total: 1 },
        {
          detections: [
            detection('d', 'medium'),
            detection('c', 'high', 'SSH brute force from 203.0.113.9'),
            detection('a', 'critical'),
          ],
          total: 3,
        },
        { detections: [detection('c', 'high'), detection('a', 'critical')], total: 2 },
      ],
    });

    await checkDetections();
    const second = await checkDetections();

    expect(second.newCount).toBe(3);
    expect(chrome.notifications.create).toHaveBeenCalledTimes(1);
    const [id, options] = chrome.notifications.create.mock.calls[0];
    expect(id).toBe('threatcrush-detections:acme');
    expect(options.message).toBe('SSH brute force from 203.0.113.9');

    // Nothing unseen on the third poll (one detection was acknowledged meanwhile).
    const third = await checkDetections();
    expect(third.newCount).toBe(2);
    expect(chrome.notifications.create).toHaveBeenCalledTimes(1);
  });

  it('does not notify for low/medium/info detections', async () => {
    const { checkDetections } = await load({
      pages: [
        { detections: [], total: 0 },
        { detections: [detection('x', 'medium'), detection('y', 'low'), detection('z', 'info')], total: 3 },
      ],
    });

    await checkDetections();
    const result = await checkDetections();

    expect(result.newCount).toBe(3);
    expect(result.urgentCount).toBe(0);
    expect(chrome.notifications.create).not.toHaveBeenCalled();
  });

  it('respects the notifications setting', async () => {
    const { checkDetections } = await load({
      pages: [{ detections: [], total: 0 }, { detections: [detection('a', 'critical')], total: 1 }],
    });
    store.notificationsEnabled = false;

    await checkDetections();
    await checkDetections();

    expect(chrome.notifications.create).not.toHaveBeenCalled();
  });

  it('re-baselines instead of notifying when the current org changes', async () => {
    const other = { id: 'org-2', slug: 'other', name: 'Other' };
    const { checkDetections } = await load({
      organizations: [ORG, other],
      pages: [{ detections: [], total: 0 }, { detections: [detection('a', 'critical')], total: 1 }],
    });

    await checkDetections();
    api.getProfile.mockResolvedValue({ profile: { current_org_id: 'org-2' } });
    const result = await checkDetections();

    expect(result.org).toEqual(other);
    expect(chrome.notifications.create).not.toHaveBeenCalled();
  });

  it('is a quiet no-op when signed out', async () => {
    const { checkDetections } = await load({ token: null });
    store.detectionAlerts = { org: ORG, newCount: 4, seenIds: ['a'] };

    const result = await checkDetections();

    expect(result).toMatchObject({ signedIn: false, org: null, newCount: 0 });
    expect(api.listOrganizations).not.toHaveBeenCalled();
    expect(store.detectionAlerts).toBeUndefined();
    expect(chrome.notifications.create).not.toHaveBeenCalled();
    expect(console.warn).not.toHaveBeenCalled();
    expect(console.error).not.toHaveBeenCalled();
  });

  it('reports no org and fetches no detections when the user has no organization', async () => {
    const { checkDetections } = await load({ organizations: [] });

    const result = await checkDetections();

    expect(result).toMatchObject({ signedIn: true, org: null, newCount: 0 });
    expect(api.listDetections).not.toHaveBeenCalled();
    expect(console.warn).not.toHaveBeenCalled();
    expect(console.error).not.toHaveBeenCalled();
  });

  it('keeps the last known state and does not notify when the API fails', async () => {
    const { checkDetections } = await load({
      pages: [
        { detections: [detection('a', 'high')], total: 1 },
        new Error('API error: 502'),
        { detections: [detection('a', 'high')], total: 1 },
      ],
    });

    await checkDetections();
    const failed = await checkDetections();

    expect(failed).toMatchObject({ org: ORG, newCount: 1, error: expect.any(String) });
    expect(store.detectionAlerts.seenIds).toEqual(['a']);

    // Recovery: the detection seen before the outage does not notify.
    await checkDetections();
    expect(chrome.notifications.create).not.toHaveBeenCalled();
  });

  it('shares one poll between concurrent callers so an alert fires once', async () => {
    const { checkDetections } = await load({
      pages: [{ detections: [], total: 0 }, { detections: [detection('a', 'critical')], total: 1 }],
    });
    await checkDetections();

    await Promise.all([checkDetections(), checkDetections()]);

    expect(api.listDetections).toHaveBeenCalledTimes(2);
    expect(chrome.notifications.create).toHaveBeenCalledTimes(1);
  });
});

describe('notification click', () => {
  it("opens the org's detections page", async () => {
    const { registerDetectionAlerts } = await load();
    registerDetectionAlerts();
    const [onClick] = chrome.notifications.onClicked.addListener.mock.calls[0];

    onClick('threatcrush-detections:acme');
    onClick('some-other-notification');

    expect(chrome.tabs.create).toHaveBeenCalledTimes(1);
    expect(chrome.tabs.create).toHaveBeenCalledWith({ url: 'https://threatcrush.com/org/acme/detections' });
  });
});
