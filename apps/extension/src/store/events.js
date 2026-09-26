import { create } from 'zustand';

/** Shape returned by the background worker's GET_STATS (see background/detections.js). */
export const EMPTY_ALERTS = {
  signedIn: false,
  org: null,
  newCount: 0,
  urgentCount: 0,
  urgentPartial: false,
  recent: [],
  checkedAt: null,
};

export const useEventsStore = create((set) => ({
  alerts: EMPTY_ALERTS,
  loading: false,

  fetchAlerts: async () => {
    set({ loading: true });
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_STATS' });
      set({ alerts: response || EMPTY_ALERTS, loading: false });
    } catch (error) {
      console.error('[ThreatCrush] Fetch alerts error:', error);
      set({ alerts: EMPTY_ALERTS, loading: false });
    }
  },
}));
