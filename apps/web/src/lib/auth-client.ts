/**
 * Client-side auth helpers. NEVER imports @/lib/supabase.
 * All auth flows go through /api/auth/* backend routes.
 * The access token is stored in localStorage and attached as a
 * Bearer header on authenticated requests.
 */

const TOKEN_KEY = "tc_access_token";

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setAccessToken(token: string | null) {
  if (typeof window === "undefined") return;
  if (token) {
    window.localStorage.setItem(TOKEN_KEY, token);
  } else {
    window.localStorage.removeItem(TOKEN_KEY);
  }
}

export function authHeaders(extra?: HeadersInit): HeadersInit {
  const token = getAccessToken();
  const headers: Record<string, string> = { ...(extra as Record<string, string>) };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return headers;
}
