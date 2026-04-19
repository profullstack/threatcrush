import { create } from 'zustand'
import { randomIP, randomCountry, formatTimestamp } from '../lib/utils'

export type EventLevel = 'info' | 'warning' | 'threat'

export interface SecurityEvent {
  id: string
  timestamp: string
  level: EventLevel
  module: string
  message: string
  sourceIP?: string
  country?: string
}

export interface ThreatSource {
  ip: string
  country: string
  hits: number
  lastSeen: string
}

export interface Module {
  name: string
  status: 'running' | 'stopped' | 'error'
  events: number
  description: string
}

interface EventStore {
  events: SecurityEvent[]
  threatSources: ThreatSource[]
  totalEvents: number
  totalThreats: number
  connectionsPerSec: number
  uptimeSeconds: number
  modules: Module[]
  addEvent: (event: SecurityEvent) => void
  incrementUptime: () => void
  generateFakeEvent: () => void
}

const MODULES: Module[] = [
  { name: 'firewall', status: 'running', events: 0, description: 'iptables/nftables monitor' },
  { name: 'ssh-guard', status: 'running', events: 0, description: 'SSH brute-force protection' },
  { name: 'port-scan', status: 'running', events: 0, description: 'Port scan detection' },
  { name: 'geo-block', status: 'running', events: 0, description: 'Geographic IP blocking' },
  { name: 'dns-filter', status: 'running', events: 0, description: 'DNS query filtering' },
  { name: 'log-watch', status: 'running', events: 0, description: 'System log analyzer' },
  { name: 'net-flow', status: 'stopped', events: 0, description: 'Network flow analysis' },
  { name: 'ids-engine', status: 'running', events: 0, description: 'Intrusion detection system' },
  { name: 'web-shield', status: 'stopped', events: 0, description: 'Web application firewall' },
  { name: 'vpn-guard', status: 'running', events: 0, description: 'VPN connection monitor' }
]

const EVENT_TEMPLATES: Array<{ level: EventLevel; module: string; messages: string[] }> = [
  {
    level: 'info',
    module: 'firewall',
    messages: [
      'Allowed outbound connection to port 443',
      'Rule updated: accept tcp dport 8080',
      'Connection tracking table cleaned',
      'Firewall rules reloaded successfully'
    ]
  },
  {
    level: 'info',
    module: 'dns-filter',
    messages: [
      'DNS query resolved: api.github.com',
      'Cache hit ratio: 87.3%',
      'Upstream resolver latency: 12ms'
    ]
  },
  {
    level: 'warning',
    module: 'ssh-guard',
    messages: [
      'Failed SSH login attempt from {ip} ({country})',
      'Multiple auth failures detected from {ip}',
      'SSH connection rate limit triggered for {ip}'
    ]
  },
  {
    level: 'warning',
    module: 'port-scan',
    messages: [
      'Sequential port scan detected from {ip}',
      'SYN flood pattern from {ip} ({country})',
      'Unusual port probe on 8443 from {ip}'
    ]
  },
  {
    level: 'threat',
    module: 'ids-engine',
    messages: [
      'BLOCKED: SQL injection attempt from {ip} ({country})',
      'BLOCKED: XSS payload detected from {ip}',
      'ALERT: Command injection attempt from {ip} ({country})'
    ]
  },
  {
    level: 'threat',
    module: 'ssh-guard',
    messages: [
      'BLOCKED: Brute force attack from {ip} ({country}) - 50+ attempts',
      'BANNED: {ip} added to blocklist (repeated violations)'
    ]
  },
  {
    level: 'info',
    module: 'log-watch',
    messages: [
      'System log rotation completed',
      'Auth log: successful sudo by user admin',
      'Kernel: network interface eth0 link up'
    ]
  },
  {
    level: 'warning',
    module: 'geo-block',
    messages: [
      'Blocked connection from {country} ({ip})',
      'Geo-fence violation: {ip} from restricted region {country}'
    ]
  },
  {
    level: 'info',
    module: 'vpn-guard',
    messages: [
      'WireGuard tunnel established: peer authenticated',
      'VPN handshake completed in 45ms',
      'Peer keepalive received'
    ]
  },
  {
    level: 'threat',
    module: 'web-shield',
    messages: [
      'BLOCKED: Directory traversal attempt from {ip}',
      'BLOCKED: Remote file inclusion from {ip} ({country})'
    ]
  }
]

let eventCounter = 0

export const useEventStore = create<EventStore>((set, get) => ({
  events: [],
  threatSources: [],
  totalEvents: 0,
  totalThreats: 0,
  connectionsPerSec: Math.floor(Math.random() * 50) + 10,
  uptimeSeconds: 0,
  modules: [...MODULES],

  addEvent: (event) =>
    set((state) => {
      const newEvents = [event, ...state.events].slice(0, 500)
      const newTotalEvents = state.totalEvents + 1
      const newTotalThreats = state.totalThreats + (event.level === 'threat' ? 1 : 0)

      // Update threat sources
      let newThreatSources = [...state.threatSources]
      if (event.sourceIP && (event.level === 'threat' || event.level === 'warning')) {
        const existing = newThreatSources.find((t) => t.ip === event.sourceIP)
        if (existing) {
          existing.hits++
          existing.lastSeen = event.timestamp
        } else {
          newThreatSources.push({
            ip: event.sourceIP,
            country: event.country || '??',
            hits: 1,
            lastSeen: event.timestamp
          })
        }
        newThreatSources = newThreatSources.sort((a, b) => b.hits - a.hits).slice(0, 20)
      }

      // Update module event counts
      const newModules = state.modules.map((m) =>
        m.name === event.module ? { ...m, events: m.events + 1 } : m
      )

      return {
        events: newEvents,
        totalEvents: newTotalEvents,
        totalThreats: newTotalThreats,
        threatSources: newThreatSources,
        modules: newModules,
        connectionsPerSec: Math.floor(Math.random() * 80) + 10
      }
    }),

  incrementUptime: () =>
    set((state) => ({ uptimeSeconds: state.uptimeSeconds + 1 })),

  generateFakeEvent: () => {
    const template = EVENT_TEMPLATES[Math.floor(Math.random() * EVENT_TEMPLATES.length)]
    // Skip events from stopped modules
    const mod = get().modules.find((m) => m.name === template.module)
    if (mod && mod.status === 'stopped') return

    const ip = randomIP()
    const country = randomCountry()
    const messageTemplate = template.messages[Math.floor(Math.random() * template.messages.length)]
    const message = messageTemplate.replace(/\{ip\}/g, ip).replace(/\{country\}/g, country)

    const event: SecurityEvent = {
      id: `evt-${++eventCounter}`,
      timestamp: formatTimestamp(new Date()),
      level: template.level,
      module: template.module,
      message,
      sourceIP: message.includes(ip) ? ip : undefined,
      country: message.includes(country) ? country : undefined
    }

    get().addEvent(event)
  }
}))
