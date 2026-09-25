import { config } from '../config';

/**
 * HTTP client for the threatcrush.com API. Every call here maps to an existing
 * route under apps/web/src/app/api; authenticated calls take the Supabase
 * access token that /api/auth/login issued.
 */

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  token?: string;
  body?: unknown;
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;

  let res: Response;
  try {
    res = await fetch(`${config.apiUrl}${path}`, {
      method: opts.method ?? 'GET',
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    });
  } catch {
    throw new ApiError(0, `Can't reach ${config.apiUrl}. Check your connection.`);
  }

  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    // Non-JSON (proxy error page, empty 204): fall through with an empty body.
  }
  const obj: Record<string, unknown> =
    body && typeof body === 'object' && !Array.isArray(body) ? (body as Record<string, unknown>) : {};

  if (!res.ok) {
    const message = typeof obj.error === 'string' && obj.error ? obj.error : `Request failed (${res.status})`;
    throw new ApiError(res.status, message, obj);
  }
  return obj as T;
}

// ─── Types (mirror the rows the web routes return) ───

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface Session {
  accessToken: string;
  refreshToken: string;
  /** Unix seconds. */
  expiresAt: number | null;
  userId: string;
  email: string | null;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  user_role: 'owner' | 'admin' | 'member';
  created_at: string;
}

export interface Server {
  id: string;
  org_id: string;
  name: string;
  hostname: string | null;
  ip_address: string | null;
  status: 'online' | 'offline' | 'unreachable';
  last_seen: string | null;
  threatcrushd_version: string | null;
  created_at: string;
}

export interface Detection {
  id: string;
  server_id: string;
  rule_id: string | null;
  severity: Severity;
  title: string;
  description: string | null;
  source_ip: string | null;
  username: string | null;
  detected_at: string;
  status: 'new' | 'acknowledged' | 'resolved';
}

export interface Remediation {
  id: string;
  server_id: string;
  detection_id: string | null;
  action_type: 'block' | 'unblock' | 'allowlist_add' | 'allowlist_remove';
  target_value: string;
  status: 'pending' | 'executed' | 'failed' | 'expired' | 'reversed';
  executed_at: string | null;
  expires_at: string | null;
  created_at: string;
}

export interface PropertyRun {
  id: string;
  property_id: string;
  type: 'scan' | 'pentest';
  status: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
  trigger: string;
  queued_at: string;
  started_at: string | null;
  completed_at: string | null;
  findings_count: number;
  severity_summary: Partial<Record<Severity, number>> | null;
  summary: string | null;
  error: string | null;
  property: { name: string; kind: string; target: string } | null;
}

interface RawSession {
  access_token?: string;
  refresh_token?: string;
  expires_at?: number | null;
}

function toSession(raw: RawSession | undefined, user: { id?: string; email?: string | null } | undefined): Session {
  if (!raw?.access_token || !raw.refresh_token || !user?.id) {
    throw new ApiError(502, 'The server returned an incomplete session. Try again.');
  }
  return {
    accessToken: raw.access_token,
    refreshToken: raw.refresh_token,
    expiresAt: raw.expires_at ?? null,
    userId: user.id,
    email: user.email ?? null,
  };
}

const page = (limit: number, offset = 0) => `limit=${limit}&offset=${offset}`;

export const api = {
  async login(email: string, password: string): Promise<Session> {
    const res = await request<{ session?: RawSession; user?: { id?: string; email?: string } }>(
      '/api/auth/login',
      { method: 'POST', body: { email, password } },
    );
    return toSession(res.session, res.user);
  },

  async refresh(refreshToken: string): Promise<Session> {
    const res = await request<{ session?: RawSession; user?: { id?: string; email?: string | null } }>(
      '/api/auth/refresh',
      { method: 'POST', body: { refresh_token: refreshToken } },
    );
    return toSession(res.session, res.user);
  },

  async currentOrgId(token: string): Promise<string | null> {
    const res = await request<{ profile?: { current_org_id?: string | null } }>('/api/auth/me', { token });
    return res.profile?.current_org_id ?? null;
  },

  async setCurrentOrg(token: string, orgId: string): Promise<void> {
    await request('/api/auth/me', { method: 'PATCH', token, body: { current_org_id: orgId } });
  },

  async listOrgs(token: string): Promise<Organization[]> {
    const res = await request<{ organizations?: Organization[] }>('/api/orgs', { token });
    return res.organizations ?? [];
  },

  async listServers(token: string, orgId: string): Promise<Server[]> {
    const res = await request<{ servers?: Server[] }>(`/api/orgs/${orgId}/servers`, { token });
    return res.servers ?? [];
  },

  async listDetections(token: string, orgId: string, limit: number, offset = 0) {
    const res = await request<{ detections?: Detection[]; total?: number }>(
      `/api/orgs/${orgId}/detections?${page(limit, offset)}`,
      { token },
    );
    return { detections: res.detections ?? [], total: res.total ?? 0 };
  },

  async listRemediations(token: string, orgId: string, limit: number) {
    const res = await request<{ remediations?: Remediation[]; total?: number }>(
      `/api/orgs/${orgId}/remediations?${page(limit)}`,
      { token },
    );
    return { remediations: res.remediations ?? [], total: res.total ?? 0 };
  },

  async listRuns(token: string, orgId: string, limit: number) {
    const res = await request<{ runs?: PropertyRun[]; total?: number }>(
      `/api/orgs/${orgId}/runs?${page(limit)}`,
      { token },
    );
    return { runs: res.runs ?? [], total: res.total ?? 0 };
  },

  async registerPushToken(token: string, orgId: string, pushToken: string, platform: 'ios' | 'android') {
    await request(`/api/orgs/${orgId}/push-subscriptions`, {
      method: 'POST',
      token,
      body: { token: pushToken, platform },
    });
  },

  async unregisterPushToken(token: string, orgId: string, pushToken: string) {
    await request(`/api/orgs/${orgId}/push-subscriptions`, {
      method: 'DELETE',
      token,
      body: { token: pushToken },
    });
  },
};
