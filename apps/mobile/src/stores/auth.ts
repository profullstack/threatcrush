import { create } from 'zustand';
import * as SecureStore from 'expo-secure-store';

interface AuthState {
  email: string | null;
  licenseKey: string | null;
  daemonUrl: string;
  isAuthenticated: boolean;
  e2eEnabled: boolean;
  publicKey: string | null;

  setEmail: (email: string | null) => void;
  setLicenseKey: (key: string | null) => void;
  setDaemonUrl: (url: string) => void;
  setE2eEnabled: (enabled: boolean) => void;
  setPublicKey: (key: string | null) => void;
  login: (email: string, key: string) => Promise<void>;
  logout: () => Promise<void>;
  loadFromStorage: () => Promise<void>;
}

const STORE_KEYS = {
  email: 'threatcrush_email',
  licenseKey: 'threatcrush_license_key',
  daemonUrl: 'threatcrush_daemon_url',
  publicKey: 'threatcrush_public_key',
};

export const useAuthStore = create<AuthState>((set) => ({
  email: null,
  licenseKey: null,
  daemonUrl: 'https://threatcrush.com',
  isAuthenticated: false,
  e2eEnabled: false,
  publicKey: null,

  setEmail: (email) => set({ email }),
  setLicenseKey: (licenseKey) => set({ licenseKey, isAuthenticated: !!licenseKey }),
  setDaemonUrl: (daemonUrl) => set({ daemonUrl }),
  setE2eEnabled: (e2eEnabled) => set({ e2eEnabled }),
  setPublicKey: (publicKey) => set({ publicKey }),

  login: async (email, key) => {
    await SecureStore.setItemAsync(STORE_KEYS.email, email);
    await SecureStore.setItemAsync(STORE_KEYS.licenseKey, key);
    set({ email, licenseKey: key, isAuthenticated: true });
  },

  logout: async () => {
    await SecureStore.deleteItemAsync(STORE_KEYS.email);
    await SecureStore.deleteItemAsync(STORE_KEYS.licenseKey);
    await SecureStore.deleteItemAsync(STORE_KEYS.publicKey);
    set({ email: null, licenseKey: null, isAuthenticated: false, publicKey: null });
  },

  loadFromStorage: async () => {
    try {
      const email = await SecureStore.getItemAsync(STORE_KEYS.email);
      const licenseKey = await SecureStore.getItemAsync(STORE_KEYS.licenseKey);
      const daemonUrl = await SecureStore.getItemAsync(STORE_KEYS.daemonUrl);
      const publicKey = await SecureStore.getItemAsync(STORE_KEYS.publicKey);
      set({
        email,
        licenseKey,
        daemonUrl: daemonUrl || 'https://threatcrush.com',
        publicKey,
        isAuthenticated: !!licenseKey,
      });
    } catch {
      // SecureStore not available (web/tests)
    }
  },
}));
