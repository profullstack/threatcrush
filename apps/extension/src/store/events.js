import { create } from 'zustand';

export const useEventsStore = create((set) => ({
  events: [],
  stats: { threats: 0, warnings: 0, eventsToday: 0, modulesRunning: 0 },
  loading: false,
  error: null,

  fetchStats: async () => {
    set({ loading: true });
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_STATS' });
      set({
        stats: response || { threats: 0, warnings: 0, eventsToday: 0, modulesRunning: 0 },
        events: [],
        loading: false,
      });
    } catch (error) {
      console.error('[ThreatCrush] Fetch stats error:', error);
      set({ stats: { threats: 0, warnings: 0, eventsToday: 0, modulesRunning: 0 }, events: [], loading: false });
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
