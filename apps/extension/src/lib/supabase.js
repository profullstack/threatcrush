import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || '';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    // Use chrome.storage for session persistence in extensions
    storage: {
      getItem: async (key) => {
        if (typeof chrome !== 'undefined' && chrome.storage) {
          const result = await chrome.storage.local.get(key);
          return result[key] || null;
        }
        return localStorage.getItem(key);
      },
      setItem: async (key, value) => {
        if (typeof chrome !== 'undefined' && chrome.storage) {
          await chrome.storage.local.set({ [key]: value });
        } else {
          localStorage.setItem(key, value);
        }
      },
      removeItem: async (key) => {
        if (typeof chrome !== 'undefined' && chrome.storage) {
          await chrome.storage.local.remove(key);
        } else {
          localStorage.removeItem(key);
        }
      },
    },
    autoRefreshToken: true,
    persistSession: true,
  },
});
