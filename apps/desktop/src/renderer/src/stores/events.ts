import { create } from 'zustand'
import { formatTimestamp } from '../lib/utils'
import type { CloudDetection, CloudServer } from '../api'

/**
 * Everything the dashboards show, from two real sources:
 *  - local: threatcrushd on this machine, over its unix socket (via the main process)
 *  - fleet: the signed-in org's servers and detections on threatcrush.com
 *
 * There is no generated or demo data here. With neither source the app says so.
 */

export type EventLevel = 'info' | 'warning' | 'threat'

export interface SecurityEvent {
  id: string
  /** Display time (HH:MM:SS). */
  timestamp: string
  /** Epoch ms, for ordering. */
  at: number
  level: EventLevel
  module: string
  message: string
  sourceIP?: string
  country?: string
  /** "this machine" or the fleet server's name. */
  origin: string
}

export interface ThreatSource {
  ip: string
  country: string
  hits: number
  lastSeen: string
}

export interface Module {
  name: string
  status: string
  events: number
  description: string
}

export type LocalState =
  | { state: 'connecting' }
  | { state: 'connected'; version?: string; socket?: string }
  | { state: 'offline'; error?: string }

export type FleetState =
  | { state: 'signed-out' }
  | { state: 'loading' }
  | { state: 'ok'; org?: string }
  | { state: 'error'; error: string }

interface EventStore {
  events: SecurityEvent[]
  threatSources: ThreatSource[]
  /** Local daemon totals (its own database), not just what is on screen. */
  totalEvents: number
  totalThreats: number
  events24h: number
  threats24h: number
  uptimeSeconds: number
  modules: Module[]
  local: LocalState
  fleet: FleetState
  servers: CloudServer[]
  fleetDetections: number
  start: () => void
  refreshFleet: () => Promise<void>
  reconnectLocal: () => Promise<void>
}

const MAX_EVENTS = 500
const LOCAL_POLL_MS = 10_000
const FLEET_POLL_MS = 30_000

interface DaemonEvent {
  id?: number
  timestamp: string | number
  module?: string
  category?: string
  severity?: string
  message?: string
  source_ip?: string
}

interface DaemonStatus {
  version?: string
  uptimeSeconds?: number
  modules?: Array<{ name: string; status: string; events: number; detail?: string }>
  counters?: Record<string, number>
}

export function levelFor(severity: string | undefined): EventLevel {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'threat'
    case 'medium':
    case 'low':
      return 'warning'
    default:
      return 'info'
  }
}

let localSeq = 0
export function fromDaemon(e: DaemonEvent): SecurityEvent {
  const at = new Date(e.timestamp).getTime() || Date.now()
  return {
    id: e.id != null ? `local-${e.id}` : `local-push-${++localSeq}-${at}`,
    timestamp: formatTimestamp(new Date(at)),
    at,
    level: levelFor(e.severity),
    module: e.module || e.category || 'daemon',
    message: e.message || e.category || 'event',
    sourceIP: e.source_ip || undefined,
    origin: 'this machine',
  }
}

export function fromDetection(d: CloudDetection, serverName: string): SecurityEvent {
  const at = Date.parse(d.detected_at) || Date.now()
  return {
    id: `fleet-${d.id}`,
    timestamp: formatTimestamp(new Date(at)),
    at,
    level: levelFor(d.severity),
    module: d.rule_id || 'detection',
    message: d.title,
    sourceIP: d.source_ip || undefined,
    origin: serverName,
  }
}

/** Merge new events in, newest first, dropping ids already shown. */
export function mergeEvents(current: SecurityEvent[], incoming: SecurityEvent[]): SecurityEvent[] {
  if (!incoming.length) return current
  const seen = new Set(current.map((e) => e.id))
  const fresh = incoming.filter((e) => !seen.has(e.id) && seen.add(e.id))
  if (!fresh.length) return current
  return [...fresh, ...current].sort((a, b) => b.at - a.at).slice(0, MAX_EVENTS)
}

export function topSources(events: SecurityEvent[], limit = 20): ThreatSource[] {
  const by = new Map<string, ThreatSource>()
  for (const e of events) {
    if (!e.sourceIP || e.level === 'info') continue
    const t = by.get(e.sourceIP)
    if (t) t.hits++
    else by.set(e.sourceIP, { ip: e.sourceIP, country: e.country || '', hits: 1, lastSeen: e.timestamp })
  }
  return [...by.values()].sort((a, b) => b.hits - a.hits).slice(0, limit)
}

let started = false
let localUnsub: (() => void) | null = null
let lastFleetSince: string | undefined

export const useEventStore = create<EventStore>((set, get) => {
  const add = (incoming: SecurityEvent[]): void => {
    const events = mergeEvents(get().events, incoming)
    if (events !== get().events) set({ events, threatSources: topSources(events) })
  }

  const applyStatus = (s: DaemonStatus): void => {
    set({
      uptimeSeconds: s.uptimeSeconds ?? get().uptimeSeconds,
      modules: (s.modules ?? []).map((m) => ({
        name: m.name,
        status: m.status,
        events: m.events,
        description: m.detail || '',
      })),
    })
  }

  const pollLocal = async (): Promise<void> => {
    const api = window.api
    if (!api) return
    if (get().local.state !== 'connected') {
      await get().reconnectLocal()
      return
    }
    const [status, counters] = await Promise.all([
      api.daemonRequest<DaemonStatus>('status'),
      api.daemonRequest<{ total: number; threats: number; last24h: number; threats24h: number }>('counters'),
    ])
    if (!status.ok) {
      set({ local: { state: 'offline', error: status.error } })
      return
    }
    applyStatus(status.result)
    if (counters.ok) {
      set({
        totalEvents: counters.result.total,
        totalThreats: counters.result.threats,
        events24h: counters.result.last24h,
        threats24h: counters.result.threats24h,
      })
    }
  }

  return {
    events: [],
    threatSources: [],
    totalEvents: 0,
    totalThreats: 0,
    events24h: 0,
    threats24h: 0,
    uptimeSeconds: 0,
    modules: [],
    local: { state: 'connecting' },
    fleet: { state: 'signed-out' },
    servers: [],
    fleetDetections: 0,

    reconnectLocal: async () => {
      const api = window.api
      if (!api) {
        set({ local: { state: 'offline', error: 'not running inside ThreatCrush Desktop' } })
        return
      }
      const conn = await api.connectDaemon().catch((err: unknown) => ({
        connected: false as const,
        error: err instanceof Error ? err.message : String(err),
        version: undefined,
        socket: undefined,
      }))
      if (!conn.connected) {
        set({ local: { state: 'offline', error: conn.error } })
        return
      }
      set({ local: { state: 'connected', version: conn.version, socket: conn.socket } })
      if (!localUnsub) {
        localUnsub = api.onEvent((frame) => {
          const f = frame as { type?: string; data?: unknown }
          if (f.type === 'event' && f.data) add([fromDaemon(f.data as DaemonEvent)])
          else if (f.type === 'disconnected') set({ local: { state: 'offline', error: 'disconnected' } })
        })
      }
      const recent = await api.daemonRequest<DaemonEvent[]>('recent_events', { limit: 300 })
      if (recent.ok) add(recent.result.map(fromDaemon))
      await pollLocal()
    },

    refreshFleet: async () => {
      const cloud = window.api?.cloud
      if (!cloud) return
      const st = await cloud.status()
      if (!st.ok || !st.result.signedIn) {
        set({ fleet: { state: 'signed-out' }, servers: [] })
        return
      }
      if (get().fleet.state !== 'ok') set({ fleet: { state: 'loading' } })
      // Signed in without an org picked yet: use the first one, as the CLI does.
      let org = st.result.org_slug
      if (!org) {
        const orgs = await cloud.orgs()
        if (!orgs.ok || !orgs.result.length) {
          set({ fleet: { state: 'error', error: orgs.ok ? 'Your account has no organization yet' : orgs.error } })
          return
        }
        await cloud.useOrg(orgs.result[0].id, orgs.result[0].slug)
        org = orgs.result[0].slug
      }
      const servers = await cloud.servers()
      if (!servers.ok) {
        set({ fleet: { state: 'error', error: servers.error } })
        return
      }
      const list = servers.result.servers ?? []
      const names = new Map(list.map((s) => [s.id, s.name || s.hostname || s.id.slice(0, 8)]))
      set({ servers: list, fleet: { state: 'ok', org } })

      const det = await cloud.detections({ limit: 200, since: lastFleetSince })
      if (det.ok) {
        const rows = det.result.detections ?? []
        if (rows.length) lastFleetSince = rows[0].detected_at
        set({ fleetDetections: Math.max(get().fleetDetections, det.result.total ?? 0) })
        add(rows.map((d) => fromDetection(d, names.get(d.server_id) ?? 'fleet server')))
      }
    },

    start: () => {
      if (started) return
      started = true
      void get().reconnectLocal()
      void get().refreshFleet()
      setInterval(() => void pollLocal(), LOCAL_POLL_MS)
      setInterval(() => void get().refreshFleet(), FLEET_POLL_MS)
      // Between polls, keep the daemon uptime ticking.
      setInterval(() => {
        if (get().local.state === 'connected') set({ uptimeSeconds: get().uptimeSeconds + 1 })
      }, 1000)
    },
  }
})
