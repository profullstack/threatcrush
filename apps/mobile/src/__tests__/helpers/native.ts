import { vi } from 'vitest';

/** In-memory keychain behind the expo-secure-store mock. */
export const secureStore = new Map<string, string>();

/** expo-notifications mock; tests set return values per case. */
export const notifications = {
  getPermissionsAsync: vi.fn(),
  requestPermissionsAsync: vi.fn(),
  getExpoPushTokenAsync: vi.fn(),
  setNotificationChannelAsync: vi.fn(),
  setNotificationHandler: vi.fn(),
  AndroidImportance: { HIGH: 4 },
};

export const platform = { OS: 'android' as string };
