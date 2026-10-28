import { useCallback, useEffect, useState } from 'react'
import { cn } from '../lib/utils'
import type { CloudFinding } from '../api'

// The org's tracked findings from threatcrush.com: what `threatcrush scan`,
// `pentest` and `ai-scan` uploaded. Same data and triage as the web app and
// `threatcrush findings`.

const VIEWS = [
  { key: 'open,acknowledged', label: 'Needs a decision' },
  { key: 'fixed', label: 'Fixed' },
  { key: 'false_positive', label: 'False positive' },
  { key: 'ignored', label: 'Ignored' },
  { key: 'all', label: 'All' },
]
const ACTIONS = [
  { status: 'acknowledged', label: 'Acknowledge' },
  { status: 'fixed', label: 'Fixed' },
  { status: 'false_positive', label: 'False positive' },
  { status: 'ignored', label: 'Ignore' },
  { status: 'open', label: 'Reopen' },
]
const SEV: Record<string, string> = {
  critical: 'bg-threat text-black', high: 'text-threat border border-threat/50', medium: 'text-yellow-400 border border-yellow-400/40',
  low: 'text-blue-400 border border-blue-400/40', info: 'text-dim border border-border',
}
const SOURCE: Record<string, string> = { scan: 'Code scan', pentest: 'Pentest', 'ai-scan': 'AI red-team' }

type Account = { signedIn: boolean; email?: string; org_slug?: string }

export default function Findings() {
  const cloud = window.api?.cloud
  const [account, setAccount] = useState<Account | null>(null)
  const [signing, setSigning] = useState<{ code: string } | null>(null)
  const [orgs, setOrgs] = useState<Array<{ id: string; slug: string; name: string }>>([])
  const [view, setView] = useState('open,acknowledged')
  const [rows, setRows] = useState<CloudFinding[]>([])
  const [counts, setCounts] = useState<Record<string, number>>({})
  const [open, setOpen] = useState<string | null>(null)
  const [detail, setDetail] = useState<Record<string, CloudFinding>>({})
  const [note, setNote] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const refreshAccount = useCallback(async () => {
    if (!cloud) return
    const s = await cloud.status()
    if (s.ok) setAccount(s.result)
    if (s.ok && s.result.signedIn) {
      const o = await cloud.orgs()
      if (o.ok) setOrgs(o.result)
    }
  }, [cloud])

  const load = useCallback(async () => {
    if (!cloud || !account?.signedIn) return
    setLoading(true)
    const r = await cloud.findings({ status: view })
    setLoading(false)
    if (!r.ok) {
      setError(r.error)
      if (/sign in/i.test(r.error)) refreshAccount()
      return
    }
    setError(null)
    setRows(r.result.findings)
    setCounts(r.result.counts || {})
  }, [cloud, account?.signedIn, view, refreshAccount])

  useEffect(() => { refreshAccount() }, [refreshAccount])
  useEffect(() => { load() }, [load])

  if (!cloud) return <div className="p-4 text-dim text-xs">Findings need ThreatCrush Desktop.</div>

  const signIn = async () => {
    setError(null)
    const r = await cloud.login()
    if (!r.ok) return setError(r.error)
    setSigning({ code: r.result.user_code })
    const w = await cloud.waitForLogin()
    setSigning(null)
    if (!w.ok) return setError(w.error)
    if (!w.result.ok) return setError(w.result.error)
    await refreshAccount()
  }

  const triage = async (ids: string[], status: string | null, withNote?: string) => {
    const r = await cloud.triage(ids, status, withNote)
    if (!r.ok) return setError(r.error)
    await load()
  }

  const expand = async (id: string) => {
    setOpen(open === id ? null : id)
    setNote(rows.find((r) => r.id === id)?.note ?? '')
    if (detail[id]) return
    const r = await cloud.finding(id)
    if (r.ok) setDetail((d) => ({ ...d, [id]: r.result.finding }))
  }

  if (!account) return <div className="p-4 text-dim text-xs">Loading…</div>

  if (!account.signedIn) {
    return (
      <div className="flex flex-col h-full p-4 gap-4 max-w-2xl">
        <div>
          <h2 className="text-lg font-bold text-text">Findings</h2>
          <p className="text-[11px] text-dim mt-0.5">Scan, pentest and AI red-team findings from your threatcrush.com org</p>
        </div>
        <div className="bg-card border border-border rounded-lg p-4 space-y-3">
          <p className="text-xs text-text">Sign in to see and triage your findings here, on the web and in the CLI.</p>
          {signing ? (
            <div className="space-y-2">
              <p className="text-xs text-dim">Approve the sign-in in your browser. Code:</p>
              <p className="text-2xl font-bold tracking-widest text-primary glow-green">{signing.code}</p>
              <button onClick={() => { cloud.cancelLogin(); setSigning(null) }} className="text-[11px] text-dim hover:text-text">Cancel</button>
            </div>
          ) : (
            <button onClick={signIn} className="px-3 py-1.5 rounded bg-primary/15 text-primary text-xs font-medium hover:bg-primary/25">
              Sign in with threatcrush.com
            </button>
          )}
          {error && <p className="text-[11px] text-threat">{error}</p>}
        </div>
      </div>
    )
  }

  const countFor = (key: string) => key === 'all' ? Object.values(counts).reduce((a, b) => a + b, 0) : key.split(',').reduce((a, k) => a + (counts[k] ?? 0), 0)

  return (
    <div className="flex flex-col h-full p-4 gap-3 overflow-hidden">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-text">Findings</h2>
          <p className="text-[11px] text-dim mt-0.5">{account.email} · gone from a later run = fixed automatically</p>
        </div>
        <div className="flex items-center gap-2">
          {orgs.length > 1 && (
            <select value={orgs.find((o) => o.slug === account.org_slug)?.id ?? ''} aria-label="Organization"
              onChange={async (e) => { const o = orgs.find((x) => x.id === e.target.value); if (o) { await cloud.useOrg(o.id, o.slug); await refreshAccount() } }}
              className="bg-card border border-border rounded px-2 py-1 text-[11px] text-text">
              {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </select>
          )}
          <button onClick={load} className="px-2 py-1 rounded border border-border text-[11px] text-dim hover:text-text">Refresh</button>
          <button onClick={async () => { await cloud.logout(); setRows([]); await refreshAccount() }} className="px-2 py-1 rounded border border-border text-[11px] text-dim hover:text-text">Sign out</button>
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {VIEWS.map((v) => (
          <button key={v.key} onClick={() => setView(v.key)}
            className={cn('px-2.5 py-1 rounded-full text-[11px] border', view === v.key ? 'bg-primary/15 text-primary border-primary/40' : 'border-border text-dim hover:text-text')}>
            {v.label} <span className="opacity-60">{countFor(v.key)}</span>
          </button>
        ))}
      </div>

      {error && <p className="text-[11px] text-threat">{error}</p>}

      <div className="flex-1 overflow-y-auto bg-card border border-border rounded-lg divide-y divide-border">
        {loading && !rows.length && <p className="p-3 text-xs text-dim">Loading…</p>}
        {!loading && !rows.length && (
          countFor('all') === 0
            ? <p className="p-3 text-xs text-dim">No findings yet. Run <span className="text-text">threatcrush login</span> then <span className="text-text">threatcrush scan .</span> or <span className="text-text">threatcrush ai-scan &lt;url&gt;</span>; every run is saved to your org.</p>
            : <p className="p-3 text-xs text-dim">Nothing in this view.</p>
        )}
        {rows.map((f) => {
          const d = detail[f.id]?.details ?? {}
          return (
            <div key={f.id} className="p-3">
              <button onClick={() => expand(f.id)} className="w-full text-left">
                <div className="flex items-center gap-2">
                  <span className={cn('px-1.5 py-0.5 rounded text-[9px] font-bold uppercase', SEV[f.severity] ?? SEV.info)}>{f.severity}</span>
                  <span className="text-xs text-text truncate">{f.message}</span>
                </div>
                <p className="text-[10px] text-dim mt-1 truncate">
                  {SOURCE[f.source] ?? f.source} · {f.properties?.name ?? '?'}{f.location ? ` · ${f.location}` : ''} · seen {f.times_seen}× · {f.status.replace('_', ' ')}
                </p>
              </button>
              {open === f.id && (
                <div className="mt-2 space-y-2">
                  {typeof d.snippet === 'string' && <pre className="bg-black/40 rounded p-2 text-[10px] text-text overflow-x-auto">{d.snippet}</pre>}
                  {typeof d.remediation === 'string' && <p className="text-[11px] text-text"><span className="text-dim">Fix: </span>{d.remediation}</p>}
                  <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} placeholder="Note"
                    className="w-full bg-black/40 border border-border rounded p-2 text-[11px] text-text" />
                  <div className="flex flex-wrap gap-1.5">
                    {ACTIONS.filter((a) => a.status !== f.status).map((a) => (
                      <button key={a.status} onClick={() => triage([f.id], a.status, note)}
                        className="px-2 py-1 rounded border border-border text-[11px] text-dim hover:text-text hover:bg-white/5">{a.label}</button>
                    ))}
                    {note !== (f.note ?? '') && (
                      <button onClick={() => triage([f.id], null, note)} className="px-2 py-1 rounded border border-border text-[11px] text-text">Save note</button>
                    )}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
