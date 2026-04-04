import { create } from 'zustand';

// Demo events for development
const DEMO_EVENTS = [
  {
    id: '1',
    type: 'scan',
    title: 'Site scan completed — example.com',
    time: '2 minutes ago',
  },
  {
    id: '2',
    type: 'info',
    title: 'Module "port-scanner" check passed',
    time: '15 minutes ago',
  },
  {
    id: '3',
    type: 'module',
    title: 'Module "ssl-monitor" updated to v1.2',
    time: '1 hour ago',
  },
  {
    id: '4',
    type: 'info',
    title: 'Daily security report generated',
    time: '3 hours ago',
  },
  {
    id: '5',
    type: 'warning',
    title: 'SSL certificate expires in 14 days',
    time: '5 hours ago',
  },
];

const DEMO_STATS = {
  threats: 0,
  warnings: 1,
  eventsToday: 12,
  modulesRunning: 3,
};

export const useEventsStore = create((set) => ({
  events: [],
  stats: { threats: 0, warnings: 0, eventsToday: 0, modulesRunning: 0 },
  loading: false,
  error: null,

  fetchStats: async () => {
    set({ loading: true });
    try {
      // TODO: Replace with real API call
      // const response = await chrome.runtime.sendMessage({ type: 'GET_STATS' });
      set({
        stats: DEMO_STATS,
        events: DEMO_EVENTS,
        loading: false,
      });
    } catch (error) {
      console.error('[ThreatCrush] Fetch stats error:', error);
      set({ loading: false, error: error.message });
    }
  },

  addEvent: (event) => {
    set((state) => ({
      events: [event, ...state.events].slice(0, 50),
    }));
  },

  clearEvents: () => {
    set({ events: [] });
  },
}));
