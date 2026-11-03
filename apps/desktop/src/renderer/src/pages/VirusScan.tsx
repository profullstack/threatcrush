import { useCallback, useEffect, useState } from 'react'
import type { AvFileView, AvQuarantineEntry, AvScanResult, AvStatus } from '../api'
import { cn } from '../lib/utils'

/** CrushAV: the free antivirus page. The engine runs in the main process. */

const OFFLINE_KEY = 'crushav.offline'
const WATCH_KEY = 'crushav.watch'

const verdictClass = (v: AvFileView['verdict']) =>
  v === 'malicious' ? 'border-red-500/60 bg-red-500/10' : v === 'suspicious' ? 'border-yellow-500/60 bg-yellow-500/10' : 'border-border'

function readFlag(key: string): boolean {
  try {
    return localStorage.getItem(key) === '1'
  } catch {
    return false
  }
}
function writeFlag(key: string, on: boolean) {
  try {
    localStorage.setItem(key, on ? '1' : '0')
  } catch {
    /* storage unavailable: setting lasts this session */
  }
}

export default function VirusScan() {
  const av = window.api?.av
  const [status, setStatus] = useState<AvStatus | null>(null)
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState<{ scanned: number; path: string; phase?: string }>({ scanned: 0, path: '' })
  const [hits, setHits] = useState<AvFileView[]>([])
  const [result, setResult] = useState<AvScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [quarantine, setQuarantine] = useState<AvQuarantineEntry[]>([])
  const [handled, setHandled] = useState<Record<string, string>>({})
  const [offline, setOffline] = useState(() => readFlag(OFFLINE_KEY))
  const [watching, setWatching] = useState(false)
  const [watchLog, setWatchLog] = useState<AvFileView[]>([])

  const refresh = useCallback(async () => {
    if (!av) return
    const [s, q] = await Promise.all([av.status(), av.quarantineList()])
    if (s.ok) {
      setStatus(s.result)
      setWatching(s.result.watching)
    }
    if (q.ok) setQuarantine(q.result)
  }, [av])

  useEffect(() => {
    if (!av) return
    void refresh()
    // Real-time protection was on last time: turn it back on.
    if (readFlag(WATCH_KEY)) void av.watch(true, readFlag(OFFLINE_KEY)).then((r) => r.ok && setWatching(r.result.watching))
    return av.onEvent((e) => {
      if (e.type === 'progress') setProgress((p) => ({ ...p, scanned: e.scanned, path: e.path }))
      else if (e.type === 'phase') setProgress((p) => ({ ...p, phase: e.detail ? `${e.phase}: ${e.detail}` : e.phase }))
      else if (e.type === 'hit') setHits((h) => [...h, e.result])
      else if (e.type === 'watch') setWatchLog((l) => [e.result, ...l].slice(0, 50))
    })
  }, [av, refresh])

  if (!av) return <div className="p-6 text-dim text-sm">Virus Scan runs in the ThreatCrush desktop app.</div>

  const start = async (mode: 'quick' | 'full' | 'paths') => {
    let paths: string[] | undefined
    if (mode === 'paths') {
      const p = await av.pick()
      if (!p.ok || !p.result.length) return
      paths = p.result
    }
    setRunning(true)
    setError(null)
    setHits([])
    setHandled({})
    setResult(null)
    setProgress({ scanned: 0, path: '' })
    const r = await av.scan(mode, paths, offline)
    setRunning(false)
    if (r.ok) setResult(r.result)
    else setError(r.error)
    void refresh()
  }

  const doQuarantine = async (path: string) => {
    const r = await av.quarantine(path)
    setHandled((h) => ({ ...h, [path]: r.ok ? 'Quarantined' : `Could not quarantine: ${r.error}` }))
    void refresh()
  }

  const toggleWatch = async () => {
    const r = await av.watch(!watching, offline)
    if (r.ok) {
      setWatching(r.result.watching)
      writeFlag(WATCH_KEY, r.result.watching)
    }
  }

  const flagged = result?.flagged ?? hits
  const watchFlagged = watchLog.filter((r) => r.verdict !== 'clean' && r.verdict !== 'error')

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-text">Virus Scan</h2>
          <p className="text-xs text-dim mt-1">
            CrushAV, free and open source. {status ? `${status.rules} detection rules` : ''}
            {status?.clamav.available ? ` + ${status.clamav.version}` : ''}.
          </p>
        </div>
        <div className="flex flex-col gap-2 text-xs">
          <label className="flex items-center gap-2 text-text">
            <input type="checkbox" checked={watching} onChange={() => void toggleWatch()} />
            Real-time protection (scan downloads as they land)
          </label>
          <label className="flex items-center gap-2 text-dim">
            <input
              type="checkbox"
              checked={offline}
              onChange={(e) => {
                setOffline(e.target.checked)
                writeFlag(OFFLINE_KEY, e.target.checked)
              }}
            />
            Offline (don&apos;t check file fingerprints online)
          </label>
        </div>
      </div>

      {status && !status.clamav.available && (
        <div className="rounded border border-border bg-card p-3 text-xs text-dim">
          Install ClamAV for millions more malware signatures, then reopen this page:
          <pre className="mt-2 whitespace-pre-wrap text-primary">{status.clamavHint}</pre>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <button disabled={running} onClick={() => void start('quick')} className="px-4 py-2 rounded bg-primary text-black text-xs font-bold disabled:opacity-40">
          Quick scan
        </button>
        <button disabled={running} onClick={() => void start('full')} className="px-4 py-2 rounded border border-border text-xs text-text hover:border-primary disabled:opacity-40">
          Full scan
        </button>
        <button disabled={running} onClick={() => void start('paths')} className="px-4 py-2 rounded border border-border text-xs text-text hover:border-primary disabled:opacity-40">
          Choose files or folders…
        </button>
        {running && (
          <button onClick={() => void av.cancel()} className="px-4 py-2 rounded border border-border text-xs text-dim hover:text-text">
            Stop
          </button>
        )}
      </div>

      {running && (
        <div className="text-xs text-dim">
          <p className="text-text">Scanning… {progress.scanned} files</p>
          {progress.phase && <p>{progress.phase}</p>}
          <p className="truncate">{progress.path}</p>
        </div>
      )}
      {error && <p className="text-xs text-threat">{error}</p>}

      {result && (
        <p className="text-xs text-text">
          {result.cancelled ? 'Stopped. ' : 'Done. '}
          {result.summary.scanned} files scanned · {result.summary.malicious} malware · {result.summary.suspicious} suspicious ·{' '}
          {result.summary.errors} unreadable
          {!result.summary.malicious && !result.summary.suspicious ? ' · nothing found' : ''}
          {result.clamavError ? ` · ClamAV error: ${result.clamavError}` : ''}
        </p>
      )}

      {flagged.length > 0 && <FileList items={flagged} handled={handled} onQuarantine={doQuarantine} onReveal={(p) => void av.reveal(p)} />}

      {watching && (
        <div>
          <h3 className="text-sm font-bold text-text">Real-time protection</h3>
          <p className="text-[11px] text-dim mt-0.5">Watching: {status?.quickTargets.join(' · ')}</p>
          {watchFlagged.length ? (
            <div className="mt-2">
              <FileList items={watchFlagged} handled={handled} onQuarantine={doQuarantine} onReveal={(p) => void av.reveal(p)} />
            </div>
          ) : (
            <p className="text-[11px] text-dim mt-1">{watchLog.length ? `${watchLog.length} new files checked, all clean.` : 'No new files yet.'}</p>
          )}
        </div>
      )}

      <div>
        <h3 className="text-sm font-bold text-text">Quarantine</h3>
        {quarantine.length === 0 ? (
          <p className="text-[11px] text-dim mt-1">Empty.</p>
        ) : (
          <ul className="mt-2 space-y-1.5">
            {quarantine.map((q) => (
              <li key={q.id} className="flex flex-wrap items-center justify-between gap-2 rounded border border-border p-2 text-[11px]">
                <div className="min-w-0">
                  <p className="truncate text-text">{q.originalPath}</p>
                  <p className="text-dim">
                    {new Date(q.quarantinedAt).toLocaleString()} · {q.detections.map((d) => d.name).join(', ') || 'manual'}
                  </p>
                </div>
                <div className="flex gap-1.5">
                  <button
                    onClick={async () => {
                      if (!confirm('Put this file back where it was? It was quarantined because it looked dangerous.')) return
                      const r = await av.restore(q.id)
                      if (!r.ok) alert(r.error)
                      void refresh()
                    }}
                    className="px-2 py-1 rounded border border-border text-dim hover:text-text"
                  >
                    Restore
                  </button>
                  <button
                    onClick={async () => {
                      if (!confirm('Delete this file permanently?')) return
                      await av.remove(q.id)
                      void refresh()
                    }}
                    className="px-2 py-1 rounded border border-border text-threat hover:text-text"
                  >
                    Delete
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

function FileList(props: {
  items: AvFileView[]
  handled: Record<string, string>
  onQuarantine: (path: string) => void
  onReveal: (path: string) => void
}) {
  return (
    <ul className="space-y-2">
      {props.items.map((r) => (
        <li key={r.path} className={cn('rounded border p-3 text-xs', verdictClass(r.verdict))}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="break-all text-text">{r.path}</span>
            <span className={cn('font-bold uppercase', r.verdict === 'malicious' ? 'text-threat' : 'text-yellow-400')}>{r.verdict === 'malicious' ? 'Malware' : 'Suspicious'}</span>
          </div>
          {r.detections
            .filter((d) => d.impact !== 'info')
            .map((d) => (
              <div key={d.id} className="mt-2">
                <p className="font-semibold text-text">{d.name}</p>
                <p className="text-dim">{d.description}</p>
              </div>
            ))}
          <div className="mt-2 flex gap-1.5">
            {props.handled[r.path] ? (
              <span className="text-dim">{props.handled[r.path]}</span>
            ) : (
              <>
                <button onClick={() => props.onQuarantine(r.path)} className="px-2 py-1 rounded bg-primary text-black font-bold">
                  Quarantine
                </button>
                <button onClick={() => props.onReveal(r.path)} className="px-2 py-1 rounded border border-border text-dim hover:text-text">
                  Show in folder
                </button>
              </>
            )}
          </div>
        </li>
      ))}
    </ul>
  )
}
