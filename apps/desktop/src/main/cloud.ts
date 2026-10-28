import { createHash, randomBytes } from 'crypto'

/**
 * threatcrush.com from the desktop app: sign-in and the org's tracked
 * findings. Runs in the main process only; the sandboxed renderer asks for
 * data over IPC and never sees a token.
 *
 * Sign-in is the CLI's link flow (/api/auth/cli/start -> approve in the
 * browser -> /api/auth/cli/token with the PKCE verifier). The desktop app
 * gets its own session rather than borrowing ~/.threatcrush/config.json:
 * refresh tokens rotate, so a shared one logs the CLI out on first refresh.
 */

export interface Session {
  token: string
  refresh_token: string
  expires_at?: number
  email?: string
  user_id?: string
  org_id?: string
  org_slug?: string
}

export interface SessionStore {
  load(): Session | null
  save(s: Session | null): void
}

export interface LoginRequest {
  request_id: string
  user_code: string
  verification_url: string
  expires_at: string
  interval: number
}

type Fetch = typeof fetch
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
export const TRIAGE_STATUSES = ['open', 'acknowledged', 'fixed', 'false_positive', 'ignored'] as const

export class CloudClient {
  private pending: { request: LoginRequest; verifier: string } | null = null

  constructor(
    private store: SessionStore,
    private api = process.env.THREATCRUSH_API_URL || 'https://threatcrush.com',
    private fetchImpl: Fetch = fetch,
    private wait: (ms: number) => Promise<void> = sleep,
  ) {}

  status(): { signedIn: boolean; email?: string; org_slug?: string; api: string } {
    const s = this.store.load()
    return { signedIn: Boolean(s?.token), email: s?.email, org_slug: s?.org_slug, api: this.api }
  }

  /** Opens a login request; the caller shows/opens `verification_url`, then calls finishLogin(). */
  async startLogin(deviceName: string): Promise<LoginRequest> {
    const verifier = randomBytes(32).toString('base64url')
    const challenge = createHash('sha256').update(verifier).digest('base64url')
    const res = await this.fetchImpl(`${this.api}/api/auth/cli/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code_challenge: challenge, code_challenge_method: 'S256', device_name: `${deviceName} (desktop)` }),
      signal: AbortSignal.timeout(15_000),
    })
    const data = (await res.json().catch(() => ({}))) as Partial<LoginRequest> & { error?: string }
    if (!res.ok || !data.request_id || !data.verification_url) throw new Error(data.error || `Could not start sign-in (${res.status})`)
    this.pending = { request: data as LoginRequest, verifier }
    return data as LoginRequest
  }

  /** Polls until the browser approves, then stores the session and picks the first org. */
  async finishLogin(now: () => number = Date.now): Promise<{ ok: true; email?: string } | { ok: false; error: string }> {
    const p = this.pending
    if (!p) return { ok: false, error: 'No sign-in in progress' }
    const deadline = Date.parse(p.request.expires_at) || now() + 10 * 60_000
    while (now() < deadline && this.pending === p) {
      await this.wait(Math.max(1, p.request.interval || 3) * 1000)
      let res: Response
      try {
        res = await this.fetchImpl(`${this.api}/api/auth/cli/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ request_id: p.request.request_id, code_verifier: p.verifier }),
          signal: AbortSignal.timeout(15_000),
        })
      } catch {
        continue
      }
      const data = (await res.json().catch(() => ({}))) as {
        status?: string; error?: string
        user?: { id?: string; email?: string }
        session?: { access_token?: string; refresh_token?: string; expires_at?: number }
      }
      if (res.ok && data.session?.access_token && data.session.refresh_token) {
        this.pending = null
        this.store.save({
          token: data.session.access_token, refresh_token: data.session.refresh_token,
          expires_at: data.session.expires_at, email: data.user?.email, user_id: data.user?.id,
        })
        const orgs = await this.orgs().catch(() => [])
        if (orgs[0]) this.useOrg(orgs[0].id, orgs[0].slug)
        return { ok: true, email: data.user?.email }
      }
      // 202 authorization_pending, a 429 from the rate limiter or a 5xx mid-deploy:
      // keep waiting. A 4xx answer (denied, expired, invalid) ends it.
      if (data.error === 'authorization_pending' || res.status === 429 || res.status >= 500 || res.ok) continue
      this.pending = null
      const why: Record<string, string> = {
        access_denied: 'The sign-in was denied in the browser.',
        expired_token: 'The sign-in link expired before it was approved.',
        invalid_grant: 'The sign-in request is no longer valid. Try again.',
      }
      return { ok: false, error: why[data.error ?? ''] ?? data.error ?? `Sign-in failed (${res.status})` }
    }
    if (this.pending === p) this.pending = null
    return { ok: false, error: 'Sign-in expired. Try again.' }
  }

  cancelLogin(): void {
    this.pending = null
  }

  logout(): void {
    this.pending = null
    this.store.save(null)
  }

  useOrg(id: string, slug: string): void {
    const s = this.store.load()
    if (s && UUID.test(id)) this.store.save({ ...s, org_id: id, org_slug: slug })
  }

  private async refresh(): Promise<boolean> {
    const s = this.store.load()
    if (!s?.refresh_token) return false
    try {
      const res = await this.fetchImpl(`${this.api}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: s.refresh_token }),
        signal: AbortSignal.timeout(15_000),
      })
      const data = (await res.json().catch(() => ({}))) as { session?: { access_token?: string; refresh_token?: string; expires_at?: number } }
      if (res.ok && data.session?.access_token && data.session.refresh_token) {
        this.store.save({ ...s, token: data.session.access_token, refresh_token: data.session.refresh_token, expires_at: data.session.expires_at })
        return true
      }
      // A refused refresh token is a dead session.
      if (res.status === 400 || res.status === 401) this.store.save(null)
    } catch {}
    return false
  }

  /** Calls our API as the signed-in user; refreshes once on 401. Only paths under /api/. */
  async call<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
    if (!path.startsWith('/api/')) throw new Error('bad path')
    let s = this.store.load()
    if (!s?.token) throw new Error('Not signed in')
    if (s.expires_at && s.expires_at - 60 < Date.now() / 1000) {
      await this.refresh()
      s = this.store.load()
      if (!s?.token) throw new Error('Session expired. Sign in again.')
    }
    const send = (token: string) => this.fetchImpl(`${this.api}${path}`, {
      method: init.method ?? 'GET',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      signal: AbortSignal.timeout(30_000),
    })
    let res = await send(s.token)
    if (res.status === 401 && (await this.refresh())) res = await send(this.store.load()!.token)
    const data = (await res.json().catch(() => ({}))) as T & { error?: string }
    if (!res.ok) throw new Error((data as { error?: string }).error || `HTTP ${res.status}`)
    return data
  }

  async orgs(): Promise<Array<{ id: string; slug: string; name: string }>> {
    const data = await this.call<{ organizations?: Array<{ id: string; slug: string; name: string }> }>('/api/orgs')
    return data.organizations ?? []
  }

  private orgId(): string {
    const id = this.store.load()?.org_id
    if (!id) throw new Error('No organization selected')
    return id
  }

  async findings(q: { status?: string; severity?: string; source?: string } = {}): Promise<unknown> {
    const qs = new URLSearchParams({ limit: '200' })
    for (const k of ['status', 'severity', 'source'] as const) {
      const v = q[k]
      if (typeof v === 'string' && /^[a-z_,-]{1,80}$/.test(v)) qs.set(k, v)
    }
    return this.call(`/api/orgs/${this.orgId()}/scan-findings?${qs}`)
  }

  async finding(id: string): Promise<unknown> {
    if (!UUID.test(id)) throw new Error('bad id')
    return this.call(`/api/orgs/${this.orgId()}/scan-findings/${id}`)
  }

  async triage(ids: unknown, status: unknown, note?: unknown): Promise<unknown> {
    const list = Array.isArray(ids) ? ids.filter((x): x is string => typeof x === 'string' && UUID.test(x)).slice(0, 500) : []
    if (!list.length) throw new Error('no ids')
    const body: Record<string, unknown> = { ids: list }
    if (status !== null && status !== undefined) {
      if (!(TRIAGE_STATUSES as readonly string[]).includes(status as string)) throw new Error('bad status')
      body.status = status
    }
    if (typeof note === 'string') body.note = note.slice(0, 4000)
    return this.call(`/api/orgs/${this.orgId()}/scan-findings`, { method: 'PATCH', body })
  }
}
