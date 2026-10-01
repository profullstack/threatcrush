import { createHash, randomBytes } from 'node:crypto';
import { hostname } from 'node:os';
import { apiUrl, updateCliConfig } from './cli-config.js';

/**
 * `threatcrush login` by link. A server has no browser and should not be
 * handed a password, so the CLI opens a request bound to a PKCE challenge,
 * prints a link for the operator to approve in a browser where they are
 * already signed in, and polls until it can redeem the request with the
 * verifier. Each machine gets its own session: refresh tokens rotate, and a
 * shared one logs every other holder out on its first refresh.
 */

export interface Pkce {
  verifier: string;
  challenge: string;
}

export function createPkce(): Pkce {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export interface LoginRequest {
  request_id: string;
  user_code: string;
  verification_url: string;
  expires_at: string;
  interval: number;
}

export async function startLinkLogin(pkce: Pkce, deviceName = hostname()): Promise<LoginRequest> {
  const res = await fetch(`${apiUrl()}/api/auth/cli/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
      device_name: deviceName,
    }),
    signal: AbortSignal.timeout(15_000),
  });
  const data = await res.json().catch(() => ({})) as Partial<LoginRequest> & { error?: string };
  if (!res.ok || !data.request_id || !data.verification_url || !data.user_code) {
    throw new Error(data.error || `Could not start login (${res.status})`);
  }
  return data as LoginRequest;
}

export type PollResult =
  | { ok: true; email: string; userId: string }
  | { ok: false; error: string };

interface TokenResponse {
  user?: { id?: string; email?: string };
  session?: { access_token?: string; refresh_token?: string; expires_at?: number };
  error?: string;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Poll until the request is approved, denied or expired. Network blips are
 * retried; only the server's answer ends the wait.
 */
export async function waitForApproval(
  request: LoginRequest,
  pkce: Pkce,
  opts: { sleepMs?: (ms: number) => Promise<void>; now?: () => number } = {},
): Promise<PollResult> {
  const wait = opts.sleepMs ?? sleep;
  const now = opts.now ?? Date.now;
  const deadline = Date.parse(request.expires_at) || now() + 10 * 60_000;
  const intervalMs = Math.max(1, request.interval || 3) * 1000;

  while (now() < deadline) {
    await wait(intervalMs);

    let res: Response;
    try {
      res = await fetch(`${apiUrl()}/api/auth/cli/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_id: request.request_id, code_verifier: pkce.verifier }),
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      continue;
    }

    const data = await res.json().catch(() => ({})) as TokenResponse;
    if (res.ok && data.session?.access_token && data.user?.id) {
      updateCliConfig({
        email: data.user.email,
        user_id: data.user.id,
        token: data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_at: data.session.expires_at,
      });
      return { ok: true, email: data.user.email || data.user.id, userId: data.user.id };
    }

    switch (data.error) {
      case 'authorization_pending':
        continue;
      case 'access_denied':
        return { ok: false, error: 'The login was denied in the browser.' };
      case 'expired_token':
        return { ok: false, error: 'The login link expired before it was approved.' };
      case 'invalid_grant':
        return { ok: false, error: 'The login request is no longer valid. Run threatcrush login again.' };
      default:
        // 429 from the rate limiter, a 5xx mid-deploy: keep waiting.
        if (res.status === 429 || res.status >= 500) continue;
        return { ok: false, error: data.error || `Login failed (${res.status})` };
    }
  }
  return { ok: false, error: 'The login link expired before it was approved.' };
}
