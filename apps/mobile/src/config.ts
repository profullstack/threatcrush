import Constants from 'expo-constants';

const extra = Constants.expoConfig?.extra ?? {};

export const config = {
  apiUrl: String(extra.apiUrl || 'https://threatcrush.com').replace(/\/$/, ''),
  appVersion: Constants.expoConfig?.version ?? 'dev',
  easProjectId: (extra.eas?.projectId as string | undefined) ?? null,
};

export const theme = {
  bg: '#0a0a0a',
  primary: '#00ff41',
  card: '#111111',
  border: '#222222',
  text: '#e0e0e0',
  dim: '#888888',
  red: '#ff4444',
  orange: '#ff8800',
  yellow: '#ffaa00',
  blue: '#4aa3ff',
} as const;
