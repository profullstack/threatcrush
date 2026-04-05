import type { ExpoConfig, ConfigContext } from 'expo/config';

const expoOwner = process.env.EXPO_OWNER || 'profullstack';
const expoProjectId = process.env.EXPO_PROJECT_ID || '6128e774-2ee6-4e21-b2d2-62a5045b813c';

export default ({ config }: ConfigContext): ExpoConfig => ({
  ...config,
  name: 'ThreatCrush',
  slug: 'threatcrush-mobile',
  scheme: 'threatcrush',
  version: '0.1.6',
  owner: expoOwner || undefined,
  orientation: 'portrait',
  icon: './assets/icon.png',
  userInterfaceStyle: 'dark',
  splash: {
    image: './assets/splash.png',
    resizeMode: 'contain',
    backgroundColor: '#0a0a0a',
  },
  ios: {
    bundleIdentifier: 'com.threatcrush.mobile',
    supportsTablet: true,
  },
  android: {
    package: 'com.threatcrush.mobile',
    adaptiveIcon: {
      foregroundImage: './assets/adaptive-icon.png',
      backgroundColor: '#0a0a0a',
    },
    permissions: ['INTERNET'],
  },
  plugins: ['expo-router', 'expo-secure-store'],
  extra: {
    apiUrl: process.env.THREATCRUSH_API_URL || 'https://threatcrush.com',
    eas: {
      projectId: expoProjectId || undefined,
    },
  },
});
