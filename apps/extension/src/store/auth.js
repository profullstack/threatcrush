import { create } from 'zustand';
import { supabase } from '../lib/supabase';

const NOT_CONFIGURED = 'Sign-in is not configured in this build (no Supabase URL/key).';

export const useAuthStore = create((set) => ({
  user: null,
  loading: true,
  error: null,

  initialize: async () => {
    if (!supabase) {
      set({ user: null, loading: false, error: NOT_CONFIGURED });
      return;
    }
    try {
      // Check for stored session
      const { data: { session } } = await supabase.auth.getSession();
      set({ user: session?.user || null, loading: false });

      // Listen for auth changes
      supabase.auth.onAuthStateChange((_event, session) => {
        set({ user: session?.user || null });
      });
    } catch (error) {
      console.error('[ThreatCrush] Auth init error:', error);
      set({ loading: false, error: error.message });
    }
  },

  login: async (email, password) => {
    if (!supabase) {
      set({ error: NOT_CONFIGURED });
      return;
    }
    set({ loading: true, error: null });
    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (error) throw error;

      set({ user: data.user, loading: false });
    } catch (error) {
      set({ loading: false, error: error.message });
    }
  },

  logout: async () => {
    if (!supabase) return;
    try {
      await supabase.auth.signOut();
      set({ user: null, error: null });
    } catch (error) {
      console.error('[ThreatCrush] Logout error:', error);
    }
  },
}));
