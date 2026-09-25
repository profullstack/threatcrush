import { beforeEach, vi } from 'vitest';
import { notifications, platform, secureStore } from './helpers/native';

vi.mock('expo-constants', () => ({
  default: {
    expoConfig: {
      version: '9.9.9',
      extra: { apiUrl: 'https://api.test/', eas: { projectId: 'eas-project-1' } },
    },
  },
}));

vi.mock('expo-secure-store', () => ({
  getItemAsync: async (key: string) => secureStore.get(key) ?? null,
  setItemAsync: async (key: string, value: string) => {
    secureStore.set(key, value);
  },
  deleteItemAsync: async (key: string) => {
    secureStore.delete(key);
  },
}));

vi.mock('expo-notifications', () => notifications);

vi.mock('react-native', () => ({ Platform: platform }));

beforeEach(() => {
  secureStore.clear();
  platform.OS = 'android';
  for (const fn of Object.values(notifications)) {
    if (typeof fn === 'function' && 'mockReset' in fn) fn.mockReset();
  }
  vi.unstubAllGlobals();
});
