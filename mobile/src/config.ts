import Constants from 'expo-constants';
import pkg from '../package.json';

export const config = {
  apiUrl: Constants.expoConfig?.extra?.apiUrl || 'https://threatcrush.com',
  appVersion: Constants.expoConfig?.version || pkg.version,
};

export const theme = {
  bg: '#0a0a0a',
  primary: '#00ff41',
  card: '#111111',
  border: '#222222',
  text: '#e0e0e0',
  dim: '#666666',
  red: '#ff4444',
  yellow: '#ffaa00',
} as const;

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export const severityColors: Record<Severity, string> = {
  low: theme.dim,
  medium: theme.yellow,
  high: '#ff8800',
  critical: theme.red,
};
