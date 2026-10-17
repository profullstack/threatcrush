import { useEffect, useRef, useState } from 'react'
import {
  type AttackMapData,
  type AttackOrigin,
  type Severity,
  MAP_ASPECT,
  demoMapData,
  maxSeverity,
  severityColor,
  topCountries,
} from '@threatcrush/attack-map'
import { type AttackMapRenderer, type MapHit, createAttackMap } from '@threatcrush/attack-map/canvas'

/**
 * Where attacks on this machine come from, live: events from the local
 * threatcrushd (pushed over its socket), placed on the globe by
 * threatcrush.com/api/geo. With no daemon it shows the labelled demo map.
 */

const API = 'https://threatcrush.com'
const REBUILD_MS = 2000

interface GeoPoint {
  lat: number
  lon: number
  city?: string
  country?: string
  countryCode?: string
}

interface DaemonEvent {
  timestamp: string | number
  severity: string
  category?: string
  source_ip?: string
}

interface Tally {
  count: number
  severity: Severity
  lastSeen: string
  category?: string
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const asSeverity = (s: string): Severity => (SEVERITIES.includes(s as Severity) ? (s as Severity) : 'info')

function isPublic(ip: string): boolean {
  if (/^(10|127|0)\.|^169\.254\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.|^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return false
  if (/^(::1?$|f[cd]|fe[89ab]|ff)/i.test(ip)) return false
  return /^[\d.]+$|:/.test(ip)
}

export default function AttackMap() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const rendererRef = useRef<AttackMapRenderer | null>(null)
  const tallies = useRef(new Map<string, Tally>())
  const geo = useRef(new Map<string, GeoPoint | null>())
  const self = useRef<GeoPoint | null>(null)
  const [data, setData] = useState<AttackMapData | null>(null)
  const [live, setLive] = useState(false)
  const [hover, setHover] = useState<{ hit: MapHit; x: number; y: number } | null>(null)

  useEffect(() => {
    if (!canvasRef.current) return
    const r = createAttackMap(canvasRef.current, { dotPitch: 6 })
    rendererRef.current = r
    return () => r.destroy()
  }, [])

  useEffect(() => {
    const api = window.api
    let stopped = false

    const record = (e: DaemonEvent): void => {
      const ip = e.source_ip
      if (!ip || !isPublic(ip)) return
      const at = new Date(e.timestamp).toISOString()
      const prev = tallies.current.get(ip)
      if (!prev) {
        tallies.current.set(ip, { count: 1, severity: asSeverity(e.severity), lastSeen: at, category: e.category })
      } else {
        prev.count++
        prev.severity = maxSeverity(prev.severity, asSeverity(e.severity))
        if (at > prev.lastSeen) {
          prev.lastSeen = at
          prev.category = e.category
        }
      }
    }

    const place = async (): Promise<void> => {
      const want = [...tallies.current.keys()].filter((ip) => !geo.current.has(ip)).slice(0, 200)
      try {
        if (!self.current) {
          const res = await fetch(`${API}/api/geo`)
          if (res.ok) self.current = ((await res.json()) as { geo: GeoPoint | null }).geo
        }
        if (want.length) {
          const res = await fetch(`${API}/api/geo`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips: want }),
          })
          if (res.ok) {
            const { results } = (await res.json()) as { results: Record<string, GeoPoint> }
            for (const ip of want) geo.current.set(ip, results[ip] ?? null)
          }
        }
      } catch {
        // Offline: try again on the next rebuild.
      }
    }

    const rebuild = async (): Promise<void> => {
      await place()
      if (stopped) return
      const origins: AttackOrigin[] = []
      for (const [ip, t] of tallies.current) {
        const g = geo.current.get(ip)
        if (g) origins.push({ ip, ...g, ...t, serverId: 'self' })
      }
      const next: AttackMapData = {
        servers: self.current ? [{ id: 'self', name: 'this machine', ...self.current, online: true }] : [],
        origins,
        windowMinutes: 0,
        generatedAt: new Date().toISOString(),
      }
      setData(next)
      rendererRef.current?.setData(next)
    }

    const showDemo = (): void => {
      const demo = demoMapData()
      setData(demo)
      rendererRef.current?.setData(demo)
    }

    let unsub: (() => void) | undefined
    let timer: ReturnType<typeof setInterval> | undefined
    ;(async () => {
      if (!api) return showDemo()
      const conn = await api.connectDaemon().catch(() => ({ connected: false }))
      if (stopped) return
      if (!conn.connected) return showDemo()
      setLive(true)
      const recent = await api.daemonRequest<DaemonEvent[]>('recent_events', { limit: 500 })
      if (recent.ok) recent.result.forEach(record)
      unsub = api.onEvent((frame) => {
        const f = frame as { type?: string; data?: DaemonEvent }
        if (f.type === 'event' && f.data) record(f.data)
      })
      await rebuild()
      timer = setInterval(() => void rebuild(), REBUILD_MS)
    })()

    return () => {
      stopped = true
      unsub?.()
      if (timer) clearInterval(timer)
    }
  }, [])

  const countries = data ? topCountries(data.origins, 5) : []
  const total = data ? data.origins.reduce((n, o) => n + o.count, 0) : 0

  return (
    <div className="flex flex-col border-b border-border">
      <div className="flex items-center gap-3 px-3 py-2 border-b border-border bg-card/50">
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-60" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
        </span>
        <span className="text-[10px] text-dim uppercase tracking-widest">Attack map</span>
        {!live && (
          <span className="rounded border border-warning/40 px-1 text-[9px] uppercase tracking-wider text-warning">
            demo — start threatcrushd
          </span>
        )}
        <span className="ml-auto text-[10px] text-dim">
          <span className="text-text font-bold">{data?.origins.length ?? 0}</span> sources ·{' '}
          <span className="text-text font-bold">{total}</span> events
        </span>
      </div>
      <div className="relative" style={{ aspectRatio: String(MAP_ASPECT) }}>
        <canvas
          ref={canvasRef}
          className="absolute inset-0 h-full w-full"
          onMouseMove={(e) => {
            const rect = e.currentTarget.getBoundingClientRect()
            const x = e.clientX - rect.left
            const y = e.clientY - rect.top
            const hit = rendererRef.current?.hitTest(x, y)
            setHover(hit ? { hit, x, y } : null)
          }}
          onMouseLeave={() => setHover(null)}
        />
        {hover && (
          <div
            className="pointer-events-none absolute z-10 rounded border border-border bg-black/90 px-2 py-1 text-[11px]"
            style={{ left: hover.x + 12, top: hover.y + 12 }}
          >
            {hover.hit.kind === 'server' ? (
              <span className="text-primary">◆ {hover.hit.server.name}</span>
            ) : (
              <>
                <div style={{ color: severityColor(hover.hit.origin.severity) }}>{hover.hit.origin.ip}</div>
                <div className="text-dim">
                  {[hover.hit.origin.city, hover.hit.origin.country].filter(Boolean).join(', ')} · {hover.hit.origin.count} events
                </div>
              </>
            )}
          </div>
        )}
        {countries.length > 0 && (
          <div className="pointer-events-none absolute bottom-2 left-2 rounded bg-black/70 px-2 py-1 text-[10px]">
            {countries.map((c) => (
              <div key={c.code ?? c.country} className="flex gap-3">
                <span className="text-dim w-5">{c.code}</span>
                <span className="text-text flex-1">{c.country}</span>
                <span className="text-threat font-bold">{c.count}</span>
              </div>
            ))}
          </div>
        )}
        <span className="pointer-events-none absolute bottom-1 right-2 text-[9px] text-dim">IP Geolocation by DB-IP</span>
      </div>
    </div>
  )
}
