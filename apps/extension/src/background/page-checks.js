/**
 * Local page checks: capture main-frame response headers, read cookie flags,
 * inspect the DOM, and set a per-tab badge. Nothing here talks to a server.
 *
 * Site access comes from the optional host permissions (PAGE_ORIGINS), granted
 * by the user from the popup or options page. Without it, clicking the toolbar
 * button still grants activeTab, which is enough for the DOM checks.
 */

import {
  PAGE_ORIGINS,
  SECURITY_HEADER_NAMES,
  badgeFor,
  isCheckableUrl,
  runPageChecks,
} from '../lib/page-checks.js';
import { collectPageSignals } from '../lib/collect-page.js';

/** Captured documents kept per tab, newest last (covers prerender and back/forward). */
const HISTORY_PER_TAB = 5;
const KEEP_HEADERS = new Set(SECURITY_HEADER_NAMES);

const NO_ACCESS = 'Needs site access. Enable page checks to read headers and cookies.';

const headersKey = (tabId) => `pageHeaders:${tabId}`;

function withoutHash(url) {
  const u = new URL(url);
  u.hash = '';
  return u.href;
}

function sitePattern(url) {
  const { protocol, hostname } = new URL(url);
  return `${protocol}//${hostname}/*`;
}

export async function hasSiteAccess(url) {
  try {
    return await chrome.permissions.contains({ origins: [sitePattern(url)] });
  } catch {
    return false;
  }
}

async function autoCheckEnabled() {
  const { autoCheck } = await chrome.storage.local.get('autoCheck');
  return autoCheck !== false;
}

/** Serialize read-modify-write of a tab's header history (redirect hops arrive back to back). */
const pendingWrites = new Map();

function onMainFrameHeaders(details) {
  if (details.tabId < 0) return Promise.resolve();
  const headers = (details.responseHeaders || [])
    .filter((h) => KEEP_HEADERS.has(h.name.toLowerCase()))
    .map((h) => ({ name: h.name, value: h.value ?? '' }));
  const url = withoutHash(details.url);
  const key = headersKey(details.tabId);
  const write = async () => {
    const stored = (await chrome.storage.session.get(key))[key] || [];
    // A redirect hop is followed by the next response for the same tab, so
    // the last entry for a URL is the document that actually rendered.
    const next = [...stored.filter((e) => e.url !== url), { url, headers }].slice(-HISTORY_PER_TAB);
    await chrome.storage.session.set({ [key]: next });
  };
  const done = (pendingWrites.get(key) || Promise.resolve()).then(write, write);
  pendingWrites.set(key, done);
  return done.finally(() => {
    if (pendingWrites.get(key) === done) pendingWrites.delete(key);
  });
}

/** Headers for the document now in the tab: exact URL, else latest same-origin. */
async function capturedHeaders(tabId, url) {
  const key = headersKey(tabId);
  const stored = (await chrome.storage.session.get(key))[key] || [];
  const target = withoutHash(url);
  const exact = stored.findLast((e) => e.url === target);
  if (exact) return exact.headers;
  // Same-document navigations (pushState) change the URL, not the response.
  const origin = new URL(url).origin;
  return stored.findLast((e) => new URL(e.url).origin === origin)?.headers ?? null;
}

async function readCookies(url) {
  let cookies;
  try {
    cookies = await chrome.cookies.getAll({ url });
  } catch (err) {
    // Firefox with first-party isolation requires firstPartyDomain.
    if (!/firstPartyDomain/.test(String(err?.message))) throw err;
    cookies = await chrome.cookies.getAll({ url, firstPartyDomain: null });
  }
  // Flags only. Cookie values never leave this function.
  return cookies.map(({ name, secure, httpOnly, sameSite }) => ({ name, secure, httpOnly, sameSite }));
}

async function inspectPage(tabId) {
  const [injection] = await chrome.scripting.executeScript({ target: { tabId }, func: collectPageSignals });
  return injection?.result ?? null;
}

async function setTabBadge(tabId, summary) {
  const { text, color } = badgeFor(summary);
  await chrome.action.setBadgeText({ tabId, text });
  await chrome.action.setBadgeBackgroundColor({ tabId, color });
}

/** Run every check against the tab's current page and update its badge. */
export async function checkTab(tabId) {
  const tab = await chrome.tabs.get(tabId);
  const url = tab.url;
  if (!url || !isCheckableUrl(url)) {
    return { url: url || null, supported: false, siteAccess: false, checks: [] };
  }

  const siteAccess = await hasSiteAccess(url);
  const unavailable = {};
  const settle = async (fn, field) => {
    try {
      return await fn();
    } catch (err) {
      unavailable[field] = `Could not be read: ${err?.message || err}`;
      return null;
    }
  };

  const [headers, cookies, page] = await Promise.all([
    siteAccess ? settle(() => capturedHeaders(tabId, url), 'headers') : null,
    siteAccess ? settle(() => readCookies(url), 'cookies') : null,
    settle(() => inspectPage(tabId), 'page'),
  ]);
  if (!siteAccess) {
    unavailable.headers = NO_ACCESS;
    unavailable.cookies = NO_ACCESS;
  } else if (!headers && !unavailable.headers) {
    unavailable.headers = 'Not captured for this page load. Reload the page to capture its response headers.';
  }

  const report = runPageChecks({ url, headers, cookies, page, unavailable });
  report.siteAccess = siteAccess;
  report.headersCaptured = Boolean(headers);
  await setTabBadge(tabId, report.summary).catch(() => {});
  return report;
}

async function onTabUpdated(tabId, changeInfo, tab) {
  if (changeInfo.status === 'loading') {
    // null clears the tab's badge (back to the empty default) until the new page is checked.
    await chrome.action.setBadgeText({ tabId, text: null }).catch(() => {});
    return;
  }
  // tab.url is only visible here when we hold host access for the page.
  if (changeInfo.status !== 'complete' || !tab.url || !isCheckableUrl(tab.url)) return;
  if (!(await autoCheckEnabled()) || !(await hasSiteAccess(tab.url))) return;
  await checkTab(tabId).catch((err) => console.warn('[ThreatCrush] Page check failed:', err));
}

/** Register listeners. Must run synchronously at worker start-up. */
export function registerPageChecks() {
  chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
      onMainFrameHeaders(details).catch((err) => console.warn('[ThreatCrush] Header capture failed:', err));
    },
    { urls: [...PAGE_ORIGINS], types: ['main_frame'] },
    ['responseHeaders']
  );
  chrome.tabs.onUpdated.addListener(onTabUpdated);
  chrome.tabs.onRemoved.addListener((tabId) => {
    chrome.storage.session.remove(headersKey(tabId)).catch(() => {});
  });
}
