"use client";

import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from "react";
import { getAccessToken, setAccessToken, authHeaders } from "./auth-client";

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
    if (!window.location.hash) {
      setHashTokenExtracted(true);
      return;
    }
    const hash = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    const accessToken = hash.get("access_token");
    if (accessToken) {
      setAccessToken(accessToken);
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
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
