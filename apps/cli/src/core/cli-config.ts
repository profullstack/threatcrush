import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export const CLI_CONFIG_DIR = join(homedir(), '.threatcrush');
export const CLI_CONFIG_PATH = join(CLI_CONFIG_DIR, 'config.json');

export interface CliConfig {
  email?: string;
  user_id?: string;
  token?: string;
  refresh_token?: string;
  expires_at?: number;
  display_name?: string;
  current_org_id?: string;
  current_org_slug?: string;
  /** The `servers` row this machine reports as (`threatcrush servers link`). */
  server_id?: string;
  /** The organization that owns `server_id`. */
  server_org_id?: string;
}

export function apiUrl(): string {
  return process.env.THREATCRUSH_API_URL || 'https://threatcrush.com';
}

export function readCliConfig(): CliConfig {
  try {
    return JSON.parse(readFileSync(CLI_CONFIG_PATH, 'utf-8')) as CliConfig;
  } catch {
    return {};
  }
}

export function writeCliConfig(config: CliConfig): void {
  if (!existsSync(CLI_CONFIG_DIR)) mkdirSync(CLI_CONFIG_DIR, { recursive: true });
  writeFileSync(CLI_CONFIG_PATH, JSON.stringify(config, null, 2), 'utf-8');
  try { chmodSync(CLI_CONFIG_PATH, 0o600); } catch { /* non-posix */ }
}

export function updateCliConfig(patch: Partial<CliConfig>): CliConfig {
  const current = readCliConfig();
  const next = { ...current, ...patch };
  writeCliConfig(next);
  return next;
}

export function clearCliConfig(keys?: Array<keyof CliConfig>): void {
  const current = readCliConfig();
  if (!keys) {
    writeCliConfig({});
    return;
  }
  for (const key of keys) delete current[key];
  writeCliConfig(current);
}

export function isLoggedIn(): boolean {
  const cfg = readCliConfig();
  if (!cfg.token) return false;
  if (cfg.expires_at && cfg.expires_at * 1000 < Date.now()) return false;
  return true;
}

/**
 * True when there is a session the daemon can use, even one whose access token
 * has expired: the refresh token can mint a new one. `isLoggedIn()` answers the
 * narrower question an interactive command asks, and gating a long-running
 * worker on it is what made the runs worker go quiet an hour after login.
 */
export function hasSession(): boolean {
  const cfg = readCliConfig();
  return Boolean(cfg.token || cfg.refresh_token);
}

export function authHeaders(): Record<string, string> {
  const cfg = readCliConfig();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (cfg.token) headers['Authorization'] = `Bearer ${cfg.token}`;
  return headers;
}

export type RefreshOutcome = 'refreshed' | 'dead' | 'unavailable';

let refreshInFlight: Promise<RefreshOutcome> | null = null;

/**
 * Trade the refresh token for a new session and write it back.
 *
 * Refresh tokens rotate: each one works exactly once. Two workers that both
 * see a 401 and both refresh would burn the token twice, and the loser would
 * log the daemon out. So every caller in this process shares one request.
 *
 * Another process (the CLI, a second daemon) may rotate it first. When the
 * server refuses ours but the file now holds a different token than the one
 * we sent, that other process won the race and its session is the live one.
 *
 * - `refreshed`: config.json holds a fresh access token.
 * - `dead`: the refresh token was refused; only `threatcrush login` helps.
 * - `unavailable`: no refresh token, or the server could not be reached.
 */
export function refreshSession(): Promise<RefreshOutcome> {
  refreshInFlight ??= doRefresh().finally(() => { refreshInFlight = null; });
  return refreshInFlight;
}

async function doRefresh(): Promise<RefreshOutcome> {
  const sent = readCliConfig().refresh_token;
  if (!sent) return 'unavailable';

  let res: Response;
  try {
    res = await fetch(`${apiUrl()}/api/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: sent }),
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    return 'unavailable';
  }

  if (res.ok) {
    const data = await res.json().catch(() => null) as {
      session?: { access_token?: string; refresh_token?: string; expires_at?: number | null };
    } | null;
    const session = data?.session;
    if (!session?.access_token || !session.refresh_token) return 'unavailable';
    updateCliConfig({
      token: session.access_token,
      refresh_token: session.refresh_token,
      expires_at: session.expires_at ?? undefined,
    });
    return 'refreshed';
  }

  if (res.status === 401 || res.status === 400) {
    return readCliConfig().refresh_token !== sent ? 'refreshed' : 'dead';
  }
  return 'unavailable';
}

/** Refresh this long before the access token's stated expiry. */
const EXPIRY_SKEW_SECONDS = 60;

/**
 * `fetch` against the ThreatCrush API as the logged-in CLI user.
 *
 * Refreshes up front when the stored token is about to expire, and on a 401
 * refreshes once and retries once. The final response is returned as-is, so a
 * caller still sees a 401 when the session is dead.
 */
export async function cloudFetch(
  path: string,
  init: { method?: string; body?: string; timeoutMs?: number } = {},
): Promise<Response> {
  const cfg = readCliConfig();
  if (cfg.refresh_token && cfg.expires_at && cfg.expires_at - EXPIRY_SKEW_SECONDS < Date.now() / 1000) {
    await refreshSession();
  }

  const send = () => fetch(`${apiUrl()}${path}`, {
    method: init.method ?? 'GET',
    headers: authHeaders(),
    body: init.body,
    signal: AbortSignal.timeout(init.timeoutMs ?? 30_000),
  });

  const res = await send();
  if (res.status !== 401) return res;
  if ((await refreshSession()) !== 'refreshed') return res;
  return send();
}
