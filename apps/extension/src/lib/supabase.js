import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || '';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

// Session persistence in chrome.storage so the popup and the background worker
// see the same sign-in.
const chromeStorage = {
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
};

// null when the build had no Supabase config (createClient throws on an empty
// URL). Page checks keep working; sign-in reports that it isn't configured.
export const supabase =
  supabaseUrl && supabaseAnonKey
    ? createClient(supabaseUrl, supabaseAnonKey, {
        auth: { storage: chromeStorage, autoRefreshToken: true, persistSession: true },
      })
    : null;
