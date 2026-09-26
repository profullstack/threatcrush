"use client";

import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from "react";
import {
  getAccessToken,
  setAccessToken,
  authHeaders,
  clearUrlHash,
  parseAuthRedirectHash,
  RESET_PASSWORD_PATH,
} from "./auth-client";

interface UserProfile {
  id: string;
  email: string;
  phone: string | null;
  display_name: string | null;
  avatar_url: string | null;
  email_verified: boolean;
  phone_verified: boolean;
  license_key: string | null;
  license_status: string;
  referral_code: string | null;
  referred_by: string | null;
  wallet_address: string | null;
  payout_crypto: string;
  total_referral_earnings_usd: number;
  notification_email: boolean;
  notification_sms: boolean;
  notification_webhook_url: string | null;
  current_org_id: string | null;
  is_admin: boolean;
  created_at: string;
  updated_at: string;
}

interface AuthContextType {
  profile: UserProfile | null;
  loading: boolean;
  signedIn: boolean;
  signOut: () => Promise<void>;
  refreshProfile: () => Promise<void>;
  currentOrgId: string | null;
  setCurrentOrgId: (orgId: string | null) => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  profile: null,
  loading: true,
  signedIn: false,
  signOut: async () => {},
  refreshProfile: async () => {},
  currentOrgId: null,
  setCurrentOrgId: async () => {},
});

export function useAuth() {
  return useContext(AuthContext);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [signedIn, setSignedIn] = useState(false);
  const [currentOrgId, setCurrentOrgIdState] = useState<string | null>(null);
  const [hashTokenExtracted, setHashTokenExtracted] = useState(false);

  // Extract OAuth tokens from URL hash (GitHub/email confirmation redirects)
  useEffect(() => {
    if (typeof window === "undefined") return;
    const redirect = parseAuthRedirectHash(window.location.hash);
    if (redirect?.kind === "recovery") {
      // A password-recovery link used to be stored here like any login, which
      // signed the user in silently and never let them set a new password.
      // GoTrue lands wherever its redirect allow-list permits (/auth/login, or
      // the site root as a fallback), so forward the link to the reset page.
      if (window.location.pathname !== RESET_PASSWORD_PATH) {
        window.location.replace(RESET_PASSWORD_PATH + window.location.hash);
        return;
      }
    } else if (redirect?.kind === "session") {
      setAccessToken(redirect.accessToken);
      clearUrlHash();
    } else if (redirect?.kind === "error" && window.location.pathname === "/") {
      // Same site-root fallback for a rejected link (expired, already used):
      // the log in page is where its reason is shown.
      window.location.replace("/auth/login" + window.location.hash);
      return;
    }
    setHashTokenExtracted(true);
  }, []);

  const fetchProfile = useCallback(async () => {
    const token = getAccessToken();
    if (!token) {
      setProfile(null);
      setSignedIn(false);
      setCurrentOrgIdState(null);
      return;
    }
    try {
      const res = await fetch("/api/auth/me", { headers: authHeaders() });
      if (res.ok) {
        const data = await res.json();
        setProfile(data.profile);
        setSignedIn(true);
        setCurrentOrgIdState(data.profile.current_org_id || null);
      } else if (res.status === 401) {
        setAccessToken(null);
        setProfile(null);
        setSignedIn(false);
        setCurrentOrgIdState(null);
      }
    } catch {
      // Network error — keep current state
    }
  }, []);

  const refreshProfile = useCallback(async () => {
    await fetchProfile();
  }, [fetchProfile]);

  const setCurrentOrgId = useCallback(async (orgId: string | null) => {
    if (!orgId) {
      setCurrentOrgIdState(null);
      // Also clear on server
      await fetch("/api/auth/me", {
        method: "PATCH",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ current_org_id: null }),
      });
      return;
    }
    try {
      const res = await fetch("/api/auth/me", {
        method: "PATCH",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ current_org_id: orgId }),
      });
      if (res.ok) {
        setCurrentOrgIdState(orgId);
        setProfile(prev => prev ? { ...prev, current_org_id: orgId } : null);
      }
    } catch {
      // Network error — ignore
    }
  }, []);

  useEffect(() => {
    if (!hashTokenExtracted) return;
    (async () => {
      await fetchProfile();
      setLoading(false);
    })();
  }, [fetchProfile, hashTokenExtracted]);

  const signOut = async () => {
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        headers: authHeaders(),
      });
    } catch {
      // ignore — we still clear locally
    }
    setAccessToken(null);
    setProfile(null);
    setSignedIn(false);
    setCurrentOrgIdState(null);
  };

  return (
    <AuthContext.Provider value={{ profile, loading, signedIn, signOut, refreshProfile, currentOrgId, setCurrentOrgId }}>
      {children}
    </AuthContext.Provider>
  );
}
