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
};
