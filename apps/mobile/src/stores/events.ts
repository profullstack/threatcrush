import { create } from 'zustand';
import type { ThreatEvent, Module, Stats } from '../lib/api';

// Demo data
const DEMO_EVENTS: ThreatEvent[] = [
  {
    id: '1',
    timestamp: new Date(Date.now() - 30000).toISOString(),
    module: 'firewall',
    severity: 'critical',
    message: 'Blocked port scan from 185.220.101.42',
    source: '185.220.101.42',
    blocked: true,
  },
  {
    id: '2',
    timestamp: new Date(Date.now() - 120000).toISOString(),
    module: 'ids',
    severity: 'high',
    message: 'SQL injection attempt detected on /api/login',
    source: '45.33.32.156',
    blocked: true,
  },
  {
    id: '3',
    timestamp: new Date(Date.now() - 300000).toISOString(),
    module: 'dns-filter',
    severity: 'medium',
    message: 'Blocked DNS query to malware-c2.evil.com',
    source: '192.168.1.105',
    blocked: true,
  },
  {
    id: '4',
    timestamp: new Date(Date.now() - 600000).toISOString(),
    module: 'firewall',
    severity: 'low',
    message: 'Rate limit applied to 203.0.113.50',
    source: '203.0.113.50',
    blocked: false,
  },
  {
    id: '5',
    timestamp: new Date(Date.now() - 900000).toISOString(),
    module: 'vpn',
    severity: 'low',
    message: 'New WireGuard peer connected: device-alpha',
    blocked: false,
  },
  {
    id: '6',
    timestamp: new Date(Date.now() - 1800000).toISOString(),
    module: 'ids',
    severity: 'high',
    message: 'Brute force SSH attempt from 198.51.100.23',
    source: '198.51.100.23',
    blocked: true,
  },
  {
    id: '7',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    module: 'dns-filter',
    severity: 'critical',
    message: 'Blocked phishing domain: login-secure-bank.xyz',
    source: '192.168.1.42',
    blocked: true,
  },
];

const DEMO_MODULES: Module[] = [
  { id: 'firewall', name: 'Firewall', description: 'Network packet filtering and port management', enabled: true, status: 'running', eventsToday: 142 },
  { id: 'ids', name: 'IDS/IPS', description: 'Intrusion detection and prevention system', enabled: true, status: 'running', eventsToday: 38 },
  { id: 'dns-filter', name: 'DNS Filter', description: 'Malicious domain blocking and DNS sinkhole', enabled: true, status: 'running', eventsToday: 67 },
  { id: 'vpn', name: 'VPN Gateway', description: 'WireGuard VPN tunnel management', enabled: true, status: 'running', eventsToday: 12 },
  { id: 'geo-block', name: 'Geo Blocker', description: 'Country-based IP blocking', enabled: false, status: 'stopped', eventsToday: 0 },
  { id: 'honeypot', name: 'Honeypot', description: 'Decoy services to detect attackers', enabled: false, status: 'stopped', eventsToday: 0 },
];

const DEMO_STATS: Stats = {
  eventsToday: 259,
  threatsBlocked: 187,
  uptimeHours: 168.5,
  modulesActive: 4,
  modulesTotal: 6,
};

interface EventsState {
  events: ThreatEvent[];
  modules: Module[];
  stats: Stats;
  loading: boolean;
  filterModule: string | null;

  setEvents: (events: ThreatEvent[]) => void;
  setModules: (modules: Module[]) => void;
  setStats: (stats: Stats) => void;
  setLoading: (loading: boolean) => void;
  setFilterModule: (module: string | null) => void;
  toggleModule: (id: string) => void;
  loadDemoData: () => void;
}

export const useEventsStore = create<EventsState>((set, get) => ({
  events: DEMO_EVENTS,
  modules: DEMO_MODULES,
  stats: DEMO_STATS,
  loading: false,
  filterModule: null,

  setEvents: (events) => set({ events }),
  setModules: (modules) => set({ modules }),
  setStats: (stats) => set({ stats }),
  setLoading: (loading) => set({ loading }),
  setFilterModule: (module) => set({ filterModule: module }),

  toggleModule: (id) =>
    set((state) => ({
      modules: state.modules.map((m) =>
        m.id === id
          ? { ...m, enabled: !m.enabled, status: m.enabled ? 'stopped' : 'running' }
          : m,
      ),
    })),

  loadDemoData: () =>
    set({
      events: DEMO_EVENTS,
      modules: DEMO_MODULES,
      stats: DEMO_STATS,
    }),
}));
