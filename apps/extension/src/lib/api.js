/**
 * ThreatCrush API client for browser extension.
 * All data routes through our API — never direct to Supabase/CoinPayPortal.
 * Sign-in itself goes through the Supabase client (store/auth.js); requests
 * here carry that session's access token.
 */

import { supabase } from './supabase.js';

const API_URL = import.meta.env.VITE_APP_URL || 'https://threatcrush.com';

async function request(path, options = {}) {
  const token = await getAuthToken();
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(error.error || `API error: ${res.status}`);
  }

  return res.json();
}

/** Access token of the signed-in Supabase session, or null. */
export async function getAuthToken() {
  if (!supabase) return null;
  try {
    const { data } = await supabase.auth.getSession();
    return data.session?.access_token || null;
  } catch {
    return null;
  }
}

// ─── Auth ───

export async function signup(email, phone, password, displayName, referralCode) {
  return request('/api/auth/signup', {
    method: 'POST',
    body: JSON.stringify({
      email,
      phone,
      password,
      display_name: displayName,
      referral_code: referralCode,
    }),
  });
}

export async function getProfile() {
  return request('/api/auth/me');
}

export async function updateProfile(updates) {
  return request('/api/auth/me', {
    method: 'PATCH',
    body: JSON.stringify(updates),
  });
}

export async function checkVerification() {
  return request('/api/auth/check');
}

// ─── Usage ───

export async function getUsageStats() {
  return request('/api/usage');
}

// ─── Modules ───

export async function getModules(params = {}) {
  const query = new URLSearchParams(params).toString();
  return request(`/api/modules${query ? `?${query}` : ''}`);
}

export async function getModule(slug) {
  return request(`/api/modules/${slug}`);
}

export async function installModule(slug) {
  return request(`/api/modules/${slug}/install`, { method: 'POST' });
}

// ─── Scanning ───

export async function scanUrl(url) {
  return request('/api/scan', {
    method: 'POST',
    body: JSON.stringify({ url }),
  });
}

/**
 * Run the code rules over a snippet.
 *
 * Server-side rather than bundling `@threatcrush/scan` into the extension.
 * The rule set is the product and it changes often; shipping it inside an
 * extension means every rule fix waits on a store review, and Chrome, Firefox
 * and Safari each review on their own schedule. The endpoint updates when the
 * web app deploys.
 *
 * `filename` is optional and only selects the language — the server never
 * opens it.
 */
export async function scanCode(content, { filename, language } = {}) {
  return request('/api/scan/code', {
    method: 'POST',
    body: JSON.stringify({
      content,
      ...(filename ? { filename } : {}),
      ...(language ? { language } : {}),
    }),
  });
}

export default {
  getAuthToken,
  signup,
  getProfile,
  updateProfile,
  checkVerification,
  getUsageStats,
  getModules,
  getModule,
  installModule,
  scanUrl,
  scanCode,
};
