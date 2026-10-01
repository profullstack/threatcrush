import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';

const saved: unknown[] = [];
vi.mock('../cli-config.js', () => ({
  apiUrl: () => 'https://threatcrush.test',
  updateCliConfig: (patch: unknown) => { saved.push(patch); return patch; },
}));

const { createPkce, startLinkLogin, waitForApproval } = await import('../link-login.js');

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

const request = {
  request_id: '00000000-0000-4000-8000-000000000000',
  user_code: 'ABCD-EFGH',
  verification_url: 'https://threatcrush.test/cli/login?request=00000000-0000-4000-8000-000000000000',
  expires_at: new Date(Date.now() + 600_000).toISOString(),
  interval: 3,
};
const noSleep = { sleepMs: async () => {} };

beforeEach(() => { saved.length = 0; });
afterEach(() => { vi.unstubAllGlobals(); });

describe('createPkce', () => {
  it('makes an S256 pair the server can check', () => {
    const { verifier, challenge } = createPkce();
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(challenge).toBe(createHash('sha256').update(verifier).digest('base64url'));
  });
});

describe('startLinkLogin', () => {
  it('sends only the challenge, never the verifier', async () => {
    const pkce = createPkce();
    const fetchMock = vi.fn(async () => json(request));
    vi.stubGlobal('fetch', fetchMock);

    expect(await startLinkLogin(pkce, 'dev2')).toEqual(request);
    const body = String((fetchMock.mock.calls[0] as unknown[] as [string, RequestInit])[1].body);
    expect(body).toContain(pkce.challenge);
    expect(body).not.toContain(pkce.verifier);
    expect(JSON.parse(body)).toMatchObject({ code_challenge_method: 'S256', device_name: 'dev2' });
  });
});

describe('waitForApproval', () => {
  it('waits through pending, blips and rate limits, then saves the session', async () => {
    const answers = [
      () => json({ error: 'authorization_pending' }, 400),
      () => { throw new Error('ECONNRESET'); },
      () => json({ error: 'too many' }, 429),
      () => json({ user: { id: 'u1', email: 'a@example.com' }, session: { access_token: 'at', refresh_token: 'rt', expires_at: 9 } }),
    ];
    vi.stubGlobal('fetch', vi.fn(async () => answers.shift()!()));

    const result = await waitForApproval(request, createPkce(), noSleep);
    expect(result).toEqual({ ok: true, email: 'a@example.com', userId: 'u1' });
    expect(saved).toEqual([{ email: 'a@example.com', user_id: 'u1', token: 'at', refresh_token: 'rt', expires_at: 9 }]);
  });

  it('stops on a denial', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ error: 'access_denied' }, 400)));
    const result = await waitForApproval(request, createPkce(), noSleep);
    expect(result).toMatchObject({ ok: false, error: expect.stringMatching(/denied/) });
    expect(saved).toEqual([]);
  });

  it('gives up when the link expires', async () => {
    let t = Date.now();
    vi.stubGlobal('fetch', vi.fn(async () => json({ error: 'authorization_pending' }, 400)));
    const result = await waitForApproval(request, createPkce(), {
      sleepMs: async () => { t += 60_000; },
      now: () => t,
    });
    expect(result).toMatchObject({ ok: false, error: expect.stringMatching(/expired/) });
  });
});
