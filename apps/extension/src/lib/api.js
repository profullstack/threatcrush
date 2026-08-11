/**
 * ThreatCrush API client for browser extension.
 * All data routes through our API — never direct to Supabase/CoinPayPortal.
 */

const API_URL = import.meta.env.VITE_APP_URL || 'https://threatcrush.com';

async function request(path, options = {}) {
  const token = await getToken();
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

async function getToken() {
  try {
    const { session } = await chrome.storage.local.get('session');
    return session?.access_token || null;
  } catch {
    return null;
  }
}

// ─── Auth ───

export async function login(email, password) {
  const data = await request('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  if (data.session) {
    await chrome.storage.local.set({ session: data.session, user: data.user });
  }
  return data;
}

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

export async function logout() {
  await chrome.storage.local.remove(['session', 'user']);
}

// ─── Usage ───

export async function getUsageStats() {
  return request('/api/usage');
}

export async function topUpCredits(amountUsd) {
  return request('/api/usage/topup', {
    method: 'POST',
    body: JSON.stringify({ amount_usd: amountUsd }),
  });
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
  login,
  signup,
  getProfile,
  updateProfile,
  checkVerification,
  logout,
  getUsageStats,
  topUpCredits,
  getModules,
  getModule,
  installModule,
  scanUrl,
  scanCode,
};
