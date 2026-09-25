import { beforeEach, describe, expect, it } from 'vitest';
import { ApiError } from '../../lib/api';
import { useAuthStore } from '../auth';
import { mockHttp } from '../../__tests__/helpers/http';
import { secureStore } from '../../__tests__/helpers/native';

const inAnHour = () => Math.floor(Date.now() / 1000) + 3600;

function loginReply(access = 'access-1', refresh = 'refresh-1', expiresAt = inAnHour()) {
  return {
    body: {
      user: { id: 'user-1', email: 'ops@example.com' },
      session: { access_token: access, refresh_token: refresh, expires_at: expiresAt },
    },
  };
}

function refreshReply(access: string, refresh: string) {
  return {
    body: {
      user: { id: 'user-1', email: 'ops@example.com' },
      session: { access_token: access, refresh_token: refresh, expires_at: inAnHour() },
    },
  };
}

function signedIn(overrides: Partial<{ accessToken: string; refreshToken: string; expiresAt: number | null }> = {}) {
  useAuthStore.setState({
    status: 'signedIn',
    session: {
      accessToken: 'access-1',
      refreshToken: 'refresh-1',
      expiresAt: inAnHour(),
      userId: 'user-1',
      email: 'ops@example.com',
      ...overrides,
    },
  });
}

describe('auth store', () => {
  beforeEach(() => {
    useAuthStore.setState({ status: 'loading', session: null });
  });

  it('signs in against /api/auth/login and survives an app restart', async () => {
    const http = mockHttp({ 'POST /api/auth/login': () => loginReply() });

    await useAuthStore.getState().signIn('  ops@example.com ', 'hunter2');

    expect(http.requests[0]).toMatchObject({
      method: 'POST',
      path: '/api/auth/login',
      body: { email: 'ops@example.com', password: 'hunter2' },
    });
    expect(useAuthStore.getState().status).toBe('signedIn');

    // Simulate a cold start: in-memory state gone, keychain intact.
    useAuthStore.setState({ status: 'loading', session: null });
    await useAuthStore.getState().restore();
    expect(useAuthStore.getState().status).toBe('signedIn');
    expect(useAuthStore.getState().session).toMatchObject({
      accessToken: 'access-1',
      refreshToken: 'refresh-1',
      email: 'ops@example.com',
    });
  });

  it('surfaces the server error and stores nothing when credentials are wrong', async () => {
    mockHttp({
      'POST /api/auth/login': () => ({ status: 401, body: { error: 'Invalid login credentials' } }),
    });

    const err = await useAuthStore.getState().signIn('ops@example.com', 'nope').catch((e: unknown) => e);

    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).message).toBe('Invalid login credentials');
    expect(useAuthStore.getState().session).toBeNull();
    expect(secureStore.size).toBe(0);
  });

  it('keeps the unverified-email flag so the login screen can explain it', async () => {
    mockHttp({
      'POST /api/auth/login': () => ({
        status: 401,
        body: { error: 'Email not confirmed', needs_email_verification: true },
      }),
    });

    const err = (await useAuthStore.getState().signIn('a@b.co', 'pw').catch((e: unknown) => e)) as ApiError;
    expect(err.body.needs_email_verification).toBe(true);
  });

  it('starts signed out when the keychain holds garbage', async () => {
    secureStore.set('threatcrush_session', '{not json');
    await useAuthStore.getState().restore();
    expect(useAuthStore.getState().status).toBe('signedOut');
  });

  it('sends the access token as a bearer header', async () => {
    signedIn();
    const http = mockHttp({ 'GET /api/orgs': () => ({ body: { organizations: [] } }) });

    await useAuthStore.getState().withSession((token) =>
      fetch('https://api.test/api/orgs', { headers: { Authorization: `Bearer ${token}` } }),
    );

    expect(http.requests[0].auth).toBe('Bearer access-1');
  });

  it('refreshes once on a 401 and retries with the rotated token', async () => {
    signedIn();
    const http = mockHttp({
      'POST /api/auth/refresh': () => refreshReply('access-2', 'refresh-2'),
    });
    const seen: string[] = [];

    const result = await useAuthStore.getState().withSession(async (token) => {
      seen.push(token);
      if (token === 'access-1') throw new ApiError(401, 'Invalid token');
      return 'ok';
    });

    expect(result).toBe('ok');
    expect(seen).toEqual(['access-1', 'access-2']);
    expect(http.requests.filter((r) => r.path === '/api/auth/refresh')).toHaveLength(1);
    expect(http.requests[0].body).toEqual({ refresh_token: 'refresh-1' });
    expect(JSON.parse(secureStore.get('threatcrush_session') ?? '{}').refreshToken).toBe('refresh-2');
  });

  it('shares one refresh between concurrent 401s (refresh tokens are single-use)', async () => {
    signedIn();
    let refreshes = 0;
    mockHttp({
      'POST /api/auth/refresh': async () => {
        refreshes++;
        return refreshReply('access-2', 'refresh-2');
      },
    });
    const call = async (token: string) => {
      if (token === 'access-1') throw new ApiError(401, 'expired');
      return token;
    };

    const results = await Promise.all([
      useAuthStore.getState().withSession(call),
      useAuthStore.getState().withSession(call),
      useAuthStore.getState().withSession(call),
    ]);

    expect(results).toEqual(['access-2', 'access-2', 'access-2']);
    expect(refreshes).toBe(1);
  });

  it('refreshes before calling when the access token is about to expire', async () => {
    signedIn({ expiresAt: Math.floor(Date.now() / 1000) + 10 });
    mockHttp({ 'POST /api/auth/refresh': () => refreshReply('access-2', 'refresh-2') });
    const seen: string[] = [];

    await useAuthStore.getState().withSession(async (token) => {
      seen.push(token);
    });

    expect(seen).toEqual(['access-2']);
  });

  it('signs out and clears the keychain when the refresh token is rejected', async () => {
    signedIn();
    secureStore.set('threatcrush_session', 'stale');
    mockHttp({
      'POST /api/auth/refresh': () => ({ status: 401, body: { error: 'Session expired. Sign in again.' } }),
    });

    const err = await useAuthStore
      .getState()
      .withSession(async () => {
        throw new ApiError(401, 'Invalid token');
      })
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(401);
    expect(useAuthStore.getState().status).toBe('signedOut');
    expect(secureStore.has('threatcrush_session')).toBe(false);
  });

  it('keeps the session when the network is down during a refresh', async () => {
    signedIn({ expiresAt: 0 });
    mockHttp();
    globalThis.fetch = (async () => {
      throw new TypeError('Network request failed');
    }) as typeof fetch;

    const err = (await useAuthStore
      .getState()
      .withSession(async () => 'unreachable')
      .catch((e: unknown) => e)) as ApiError;

    expect(err.status).toBe(0);
    expect(useAuthStore.getState().status).toBe('signedIn');
  });
});
