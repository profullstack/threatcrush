import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

beforeEach(() => {
  vi.resetModules();
  global.chrome = { storage: { local: { get: vi.fn().mockResolvedValue({}), set: vi.fn(), remove: vi.fn() } } };
  global.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
});

afterEach(() => {
  vi.doUnmock('../src/lib/supabase.js');
});

describe('API auth', () => {
  it('sends the signed-in Supabase session token with API requests', async () => {
    vi.doMock('../src/lib/supabase.js', () => ({
      supabase: {
        auth: { getSession: async () => ({ data: { session: { access_token: 'jwt-from-supabase' } } }) },
      },
    }));
    const { getUsageStats } = await import('../src/lib/api.js');

    await getUsageStats();

    const [, init] = fetch.mock.calls[0];
    expect(init.headers.Authorization).toBe('Bearer jwt-from-supabase');
  });

  it('sends no Authorization header when signed out', async () => {
    vi.doMock('../src/lib/supabase.js', () => ({
      supabase: { auth: { getSession: async () => ({ data: { session: null } }) } },
    }));
    const { getUsageStats } = await import('../src/lib/api.js');

    await getUsageStats();

    expect(fetch.mock.calls[0][1].headers).not.toHaveProperty('Authorization');
  });
});

describe('build without Supabase config', () => {
  it('reports sign-in as not configured instead of failing to load', async () => {
    // The test build defines no VITE_SUPABASE_URL, like a CI build without secrets.
    const { useAuthStore } = await import('../src/store/auth.js');

    await useAuthStore.getState().initialize();

    const state = useAuthStore.getState();
    expect(state.loading).toBe(false);
    expect(state.user).toBeNull();
    expect(state.error).toMatch(/not configured/i);
  });
});
