import { create } from 'zustand';
import { Platform } from 'react-native';
import * as Notifications from 'expo-notifications';
import { api } from '../lib/api';
import { config } from '../config';
import { useAuthStore } from './auth';

export const ANDROID_CHANNEL_ID = 'threat-alerts';

/**
 * - undetermined: we may still ask (show the explanation card first)
 * - denied: the OS won't ask again; only system Settings can turn it on
 * - enabled: this device's Expo token is registered for `orgId`
 * - unsupported: no push on this platform/build (web, missing EAS project id)
 */
type PushStatus = 'unknown' | 'undetermined' | 'denied' | 'enabled' | 'unsupported' | 'error';

interface PushState {
  status: PushStatus;
  token: string | null;
  orgId: string | null;
  error: string | null;
  /** The user tapped "Not now" on the explanation card this session. */
  dismissed: boolean;

  /** Register silently if permission was already granted; never prompts. */
  sync: (orgId: string) => Promise<void>;
  /** Ask for permission (after the in-app explanation), then register. */
  enable: (orgId: string) => Promise<void>;
  /** Unregister this device (sign-out). Best effort. */
  unregister: () => Promise<void>;
  dismiss: () => void;
}

const platform = (): 'ios' | 'android' | null =>
  Platform.OS === 'ios' || Platform.OS === 'android' ? Platform.OS : null;

export const usePushStore = create<PushState>((set, get) => ({
  status: 'unknown',
  token: null,
  orgId: null,
  error: null,
  dismissed: false,

  sync: async (orgId) => {
    const os = platform();
    if (!os || !config.easProjectId) {
      set({ status: 'unsupported' });
      return;
    }
    try {
      const perm = await Notifications.getPermissionsAsync();
      if (perm.status !== 'granted') {
        set({ status: perm.canAskAgain ? 'undetermined' : 'denied' });
        return;
      }
      if (get().status === 'enabled' && get().orgId === orgId) return;

      const { data: token } = await Notifications.getExpoPushTokenAsync({
        projectId: config.easProjectId,
      });
      await useAuthStore
        .getState()
        .withSession((accessToken) => api.registerPushToken(accessToken, orgId, token, os));
      set({ status: 'enabled', token, orgId, error: null });
    } catch (err) {
      set({ status: 'error', error: err instanceof Error ? err.message : String(err) });
    }
  },

  enable: async (orgId) => {
    if (!platform()) {
      set({ status: 'unsupported' });
      return;
    }
    try {
      if (Platform.OS === 'android') {
        // Android 13+ only shows the permission prompt once a channel exists.
        await Notifications.setNotificationChannelAsync(ANDROID_CHANNEL_ID, {
          name: 'Threat alerts',
          importance: Notifications.AndroidImportance.HIGH,
        });
      }
      await Notifications.requestPermissionsAsync();
    } catch (err) {
      set({ status: 'error', error: err instanceof Error ? err.message : String(err) });
      return;
    }
    await get().sync(orgId);
  },

  unregister: async () => {
    const { token, orgId } = get();
    set({ status: 'unknown', token: null, orgId: null, error: null, dismissed: false });
    if (!token || !orgId || !useAuthStore.getState().session) return;
    await useAuthStore
      .getState()
      .withSession((accessToken) => api.unregisterPushToken(accessToken, orgId, token))
      .catch(() => undefined);
  },

  dismiss: () => set({ dismissed: true }),
}));
