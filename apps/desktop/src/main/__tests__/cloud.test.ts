import { describe, expect, it } from 'vitest'
import { CloudClient, type Session } from '../cloud'

const ORG = '0b9c3f2e-6a1d-4c55-9f3e-2d4b8a7c1e90'
const ID = '11111111-2222-4333-8444-555555555555'

function memStore(initial: Session | null = null) {
  let s = initial
  return { load: () => s, save: (n: Session | null) => { s = n } }
}

type Call = { url: string; method: string; auth?: string; body?: unknown }
function fakeApi(handler: (c: Call) => { status: number; body: unknown }) {
  const calls: Call[] = []
  const f = (async (url: string, init: RequestInit = {}) => {
    const headers = (init.headers ?? {}) as Record<string, string>
    const c = { url, method: init.method ?? 'GET', auth: headers.Authorization, body: init.body ? JSON.parse(String(init.body)) : undefined }
    calls.push(c)
    const r = handler(c)
    return new Response(JSON.stringify(r.body), { status: r.status })
  }) as typeof fetch
  return { calls, f }
}
const noWait = async () => {}

describe('CloudClient sign-in', () => {
  it('waits through authorization_pending and a 5xx, stores the session and picks the first org', async () => {
    let polls = 0
    const { calls, f } = fakeApi((c) => {
      if (c.url.endsWith('/api/auth/cli/start')) return { status: 200, body: { request_id: 'r1', user_code: 'ABCD', verification_url: 'https://tc/approve', expires_at: new Date(Date.now() + 60_000).toISOString(), interval: 1 } }
      if (c.url.endsWith('/api/auth/cli/token')) {
        polls++
        if (polls === 1) return { status: 202, body: { error: 'authorization_pending' } }
        if (polls === 2) return { status: 503, body: {} }
        return { status: 200, body: { user: { id: 'u1', email: 'a@b.c' }, session: { access_token: 'at', refresh_token: 'rt' } } }
      }
      if (c.url.endsWith('/api/orgs')) return { status: 200, body: { organizations: [{ id: ORG, slug: 'acme', name: 'Acme' }] } }
      return { status: 404, body: {} }
    })
    const store = memStore()
    const c = new CloudClient(store, 'https://tc', f, noWait)
    const req = await c.startLogin('box')
    expect(req.user_code).toBe('ABCD')
    expect(calls[0].body).toMatchObject({ code_challenge_method: 'S256', device_name: 'box (desktop)' })
    expect(await c.finishLogin()).toEqual({ ok: true, email: 'a@b.c' })
    expect(store.load()).toMatchObject({ token: 'at', refresh_token: 'rt', org_id: ORG, org_slug: 'acme' })
    expect(c.status()).toMatchObject({ signedIn: true, email: 'a@b.c', org_slug: 'acme' })
  })

  it('a denied sign-in ends with a readable error', async () => {
    const { f } = fakeApi((c) => c.url.endsWith('/start')
      ? { status: 200, body: { request_id: 'r', user_code: 'X', verification_url: 'https://tc/a', expires_at: new Date(Date.now() + 60_000).toISOString(), interval: 1 } }
      : { status: 400, body: { error: 'access_denied' } })
    const c = new CloudClient(memStore(), 'https://tc', f, noWait)
    await c.startLogin('box')
    expect(await c.finishLogin()).toEqual({ ok: false, error: 'The sign-in was denied in the browser.' })
  })
})

describe('CloudClient API calls', () => {
  const signedIn = () => memStore({ token: 'old', refresh_token: 'rt', org_id: ORG, org_slug: 'acme' })

  it('refreshes once on a 401 and retries with the new token', async () => {
    const { calls, f } = fakeApi((c) => {
      if (c.url.endsWith('/api/auth/refresh')) return { status: 200, body: { session: { access_token: 'new', refresh_token: 'rt2' } } }
      return c.auth === 'Bearer new' ? { status: 200, body: { findings: [], total: 0, counts: {} } } : { status: 401, body: { error: 'expired' } }
    })
    const store = signedIn()
    await new CloudClient(store, 'https://tc', f, noWait).findings({ status: 'open' })
    expect(calls.map((c) => c.auth ?? 'refresh')).toEqual(['Bearer old', 'refresh', 'Bearer new'])
    expect(store.load()).toMatchObject({ token: 'new', refresh_token: 'rt2' })
  })

  it('a refused refresh signs out', async () => {
    const { f } = fakeApi((c) => c.url.endsWith('/refresh') ? { status: 401, body: {} } : { status: 401, body: { error: 'expired' } })
    const store = signedIn()
    await expect(new CloudClient(store, 'https://tc', f, noWait).findings()).rejects.toThrow()
    expect(store.load()).toBeNull()
  })

  it('validates what the renderer sends before anything leaves', async () => {
    const { calls, f } = fakeApi(() => ({ status: 200, body: { updated: [] } }))
    const c = new CloudClient(signedIn(), 'https://tc', f, noWait)
    await expect(c.triage(['../../etc'], 'fixed')).rejects.toThrow('no ids')
    await expect(c.triage([ID], 'deleted')).rejects.toThrow('bad status')
    await expect(c.finding('x/../../admin')).rejects.toThrow('bad id')
    await expect(c.call('https://evil/api')).rejects.toThrow('bad path')
    expect(calls).toHaveLength(0)
    await c.triage([ID, 'junk'], 'false_positive', 'fixture')
    expect(calls[0]).toMatchObject({ method: 'PATCH', url: `https://tc/api/orgs/${ORG}/scan-findings`, body: { ids: [ID], status: 'false_positive', note: 'fixture' } })
  })

  it('drops filter values that are not plain lists', async () => {
    const { calls, f } = fakeApi(() => ({ status: 200, body: {} }))
    await new CloudClient(signedIn(), 'https://tc', f, noWait).findings({ status: 'open&limit=99999', severity: 'high' })
    expect(calls[0].url).toBe(`https://tc/api/orgs/${ORG}/scan-findings?limit=200&severity=high`)
  })

  it('passes a paging offset only when it is a sane integer', async () => {
    const { calls, f } = fakeApi(() => ({ status: 200, body: {} }))
    const c = new CloudClient(signedIn(), 'https://tc', f, noWait)
    await c.findings({ offset: 200 })
    await c.findings({ offset: -5 })
    await c.findings({ offset: 1.5 })
    expect(calls.map((x) => new URL(x.url).searchParams.get('offset'))).toEqual(['200', null, null])
  })

  it('needs a session and an org', async () => {
    const { f } = fakeApi(() => ({ status: 200, body: {} }))
    await expect(new CloudClient(memStore(), 'https://tc', f, noWait).orgs()).rejects.toThrow('Not signed in')
    await expect(new CloudClient(memStore({ token: 't', refresh_token: 'r' }), 'https://tc', f, noWait).finding(ID)).rejects.toThrow('No organization selected')
  })
})
