import { useState } from 'react'
import { cn } from '../lib/utils'
import { useEventStore } from '../stores/events'

// The signed-in org's servers on threatcrush.com, with their recent detections.
// Same data as `threatcrush servers` and the web dashboard.

function ago(iso: string | null): string {
  if (!iso) return 'never'
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.round(s / 60)}m ago`
  if (s < 86400) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

export default function Fleet() {
  const cloud = window.api?.cloud
  const fleet = useEventStore((s) => s.fleet)
  const servers = useEventStore((s) => s.servers)
  const events = useEventStore((s) => s.events)
  const refresh = useEventStore((s) => s.refreshFleet)
  const [signing, setSigning] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  if (!cloud) return <div className="p-4 text-dim text-xs">Fleet needs ThreatCrush Desktop.</div>

  const signIn = async (): Promise<void> => {
    setError(null)
    const r = await cloud.login()
    if (!r.ok) return setError(r.error)
    setSigning(r.result.user_code)
    const w = await cloud.waitForLogin()
    setSigning(null)
    if (!w.ok) return setError(w.error)
    if (!w.result.ok) return setError(w.result.error)
    await refresh()
  }

  const online = servers.filter((s) => s.status === 'online').length
  const recentBy = new Map<string, number>()
  for (const e of events) {
    if (e.id.startsWith('fleet-') && e.level !== 'info') recentBy.set(e.origin, (recentBy.get(e.origin) ?? 0) + 1)
  }

  return (
    <div className="flex flex-col h-full p-4 gap-4 overflow-y-auto">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-text">Fleet</h2>
          <p className="text-[11px] text-dim mt-0.5">
            {fleet.state === 'ok'
              ? `${online}/${servers.length} servers online${fleet.org ? ` in /${fleet.org}` : ''}`
              : 'Your servers running threatcrushd, from threatcrush.com'}
          </p>
        </div>
        {fleet.state === 'ok' && (
          <button
            onClick={() => void refresh()}
            className="px-3 py-1 text-[10px] font-bold text-primary border border-primary/30 rounded hover:bg-primary/10"
          >
            REFRESH
          </button>
        )}
      </div>

      {(error || fleet.state === 'error') && (
        <div className="text-[11px] text-threat">{error ?? (fleet.state === 'error' ? fleet.error : '')}</div>
      )}

      {fleet.state === 'signed-out' && (
        <div className="bg-card border border-border rounded-lg p-4 text-[11px] text-dim max-w-xl">
          <p className="text-text mb-2">Sign in to see your servers.</p>
          <p>Uses the same threatcrush.com account as <code className="text-primary">threatcrush login</code>.</p>
          {signing ? (
            <p className="mt-3">
              Approve in your browser. Code: <span className="text-primary font-bold">{signing}</span>
            </p>
          ) : (
            <button
              onClick={() => void signIn()}
              className="mt-3 px-3 py-1 text-[10px] font-bold text-primary border border-primary/30 rounded hover:bg-primary/10"
            >
              SIGN IN WITH THREATCRUSH.COM
            </button>
          )}
        </div>
      )}

      {fleet.state === 'loading' && <div className="text-dim text-xs">Loading servers...</div>}

      {fleet.state === 'ok' && servers.length === 0 && (
        <div className="text-dim text-xs">
          No servers yet. On a server, run <code className="text-primary">threatcrush link</code> to add it.
        </div>
      )}

      {fleet.state === 'ok' && servers.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full text-[11px]">
            <thead>
              <tr className="text-dim text-[10px] uppercase tracking-wider border-b border-border">
                <th className="text-left px-3 py-2">Server</th>
                <th className="text-left px-3 py-2">Status</th>
                <th className="text-left px-3 py-2">Last seen</th>
                <th className="text-left px-3 py-2">Daemon</th>
                <th className="text-right px-3 py-2">Recent alerts</th>
              </tr>
            </thead>
            <tbody>
              {servers.map((s) => {
                const name = s.name || s.hostname || s.id.slice(0, 8)
                return (
                  <tr key={s.id} className="border-b border-border/50 hover:bg-white/[0.02]">
                    <td className="px-3 py-2">
                      <div className="text-text font-bold">{name}</div>
                      {s.hostname && s.hostname !== name && <div className="text-dim">{s.hostname}</div>}
                    </td>
                    <td className="px-3 py-2">
                      <span className={cn(
                        'font-bold uppercase',
                        s.status === 'online' ? 'text-primary' : s.status === 'unreachable' ? 'text-threat' : 'text-dim'
                      )}>
                        {s.status}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-dim">{ago(s.last_seen)}</td>
                    <td className="px-3 py-2 text-dim">{s.threatcrushd_version ?? '-'}</td>
                    <td className="px-3 py-2 text-right text-text">{recentBy.get(name) ?? 0}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
