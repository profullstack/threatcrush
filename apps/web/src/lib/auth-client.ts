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

/** Where a password-recovery link is handled, whichever page GoTrue lands on. */
export const RESET_PASSWORD_PATH = "/auth/reset-password";

/** What GoTrue put in the URL hash when it redirected back to us. */
export type AuthRedirect =
  /** A normal sign-in (email confirmation, OAuth): the token is the login session. */
  | { kind: "session"; accessToken: string }
  /**
   * A password-recovery link. The session exists only to set a new password;
   * it must never become the stored login.
   */
  | { kind: "recovery"; accessToken: string }
  /** GoTrue rejected the link, e.g. "Email link is invalid or has expired". */
  | { kind: "error"; message: string };

/** Parses a `location.hash` from a GoTrue redirect; null when it carries none. */
export function parseAuthRedirectHash(hash: string): AuthRedirect | null {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const accessToken = params.get("access_token");
  if (accessToken) {
    return params.get("type") === "recovery"
      ? { kind: "recovery", accessToken }
      : { kind: "session", accessToken };
  }
  const error = params.get("error_description") || params.get("error");
  return error ? { kind: "error", message: error } : null;
}

/** Drops the hash so tokens do not linger in the address bar or history. */
export function clearUrlHash() {
  window.history.replaceState(null, "", window.location.pathname + window.location.search);
}
