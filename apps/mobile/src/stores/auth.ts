import { create } from 'zustand';
import * as SecureStore from 'expo-secure-store';
import { api, ApiError, type Session } from '../lib/api';

const SESSION_KEY = 'threatcrush_session';

/** Refresh this long before the access token actually expires. */
const REFRESH_MARGIN_MS = 60_000;

type AuthStatus = 'loading' | 'signedOut' | 'signedIn';

interface AuthState {
  status: AuthStatus;
  session: Session | null;

  /** Load a saved session from the keychain (app start). */
  restore: () => Promise<void>;
  signIn: (email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  /**
   * Run an authenticated API call with a fresh access token. Refreshes once on
   * expiry or a 401; if the refresh token is rejected the user is signed out.
   */
  withSession: <T>(call: (accessToken: string) => Promise<T>) => Promise<T>;
}

function isSession(value: unknown): value is Session {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.accessToken === 'string' &&
    typeof v.refreshToken === 'string' &&
    typeof v.userId === 'string'
  );
}

async function persist(session: Session | null) {
  if (session) await SecureStore.setItemAsync(SESSION_KEY, JSON.stringify(session));
  else await SecureStore.deleteItemAsync(SESSION_KEY);
}

// Refresh tokens rotate on use, so two concurrent refreshes with the same
// token would get the second one rejected and sign the user out. Every caller
// shares the one in flight.
let refreshing: Promise<Session> | null = null;

export const useAuthStore = create<AuthState>((set, get) => {
  const refresh = (stale: Session): Promise<Session> => {
    refreshing ??= (async () => {
      try {
        const next = await api.refresh(stale.refreshToken);
        await persist(next);
        set({ session: next, status: 'signedIn' });
        return next;
      } catch (err) {
        if (err instanceof ApiError && (err.status === 401 || err.status === 400)) {
          await get().signOut();
          throw new ApiError(401, 'Your session expired. Sign in again.');
        }
        throw err;
      } finally {
        refreshing = null;
      }
    })();
    return refreshing;
  };

  return {
    status: 'loading',
    session: null,

    restore: async () => {
      let session: Session | null = null;
      try {
        const raw = await SecureStore.getItemAsync(SESSION_KEY);
        const parsed: unknown = raw ? JSON.parse(raw) : null;
        session = isSession(parsed) ? parsed : null;
      } catch {
        session = null;
      }
      set({ session, status: session ? 'signedIn' : 'signedOut' });
    },

    signIn: async (email, password) => {
      const session = await api.login(email.trim(), password);
      await persist(session);
      set({ session, status: 'signedIn' });
    },

    signOut: async () => {
      set({ session: null, status: 'signedOut' });
      await persist(null);
    },

    withSession: async (call) => {
      let session = get().session;
      if (!session) throw new ApiError(401, 'Not signed in.');

      if (session.expiresAt !== null && session.expiresAt * 1000 - Date.now() < REFRESH_MARGIN_MS) {
        session = await refresh(session);
      }

      try {
        return await call(session.accessToken);
      } catch (err) {
        if (!(err instanceof ApiError) || err.status !== 401) throw err;
        // Another caller may already have rotated the token while this request
        // was in flight; only refresh if we're still holding the rejected one.
        const current = get().session;
        if (!current) throw err;
        const fresh =
          current.accessToken === session.accessToken ? await refresh(current) : current;
        return call(fresh.accessToken);
      }
    },
  };
});
