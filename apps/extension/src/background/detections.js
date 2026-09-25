/**
 * Account alerts: poll the signed-in user's org for `new` detections, keep the
 * count for the popup and toolbar tooltip, and raise a browser notification
 * for high/critical detections that appeared since the previous poll.
 *
 * New detections are found by diffing detection ids against the previous poll
 * rather than with `since=<last check>`: `since` filters on `detected_at`,
 * which the daemon sets and which can predate the upload (spooled events are
 * replayed later), so a time window would silently drop them.
 */

import { getAuthToken, getProfile, listDetections, listOrganizations } from '../lib/api.js';

const APP_URL = import.meta.env.VITE_APP_URL || 'https://threatcrush.com';

export const STATE_KEY = 'detectionAlerts';
export const NOTIFICATION_PREFIX = 'threatcrush-detections:';
export const ALERT_SEVERITIES = new Set(['high', 'critical']);
/** Newest `new` detections fetched per poll; the route's maximum is 200. */
const PAGE_SIZE = 100;
const RECENT_SHOWN = 5;
const DEFAULT_TITLE = 'ThreatCrush';

/** Popup/tooltip view of the last poll. */
function summary(state) {
  if (!state) {
    return { signedIn: false, org: null, newCount: 0, urgentCount: 0, urgentPartial: false, recent: [], checkedAt: null };
  }
  return {
    signedIn: true,
    org: state.org,
    newCount: state.newCount,
    urgentCount: state.urgentCount,
    urgentPartial: state.urgentPartial,
    recent: state.recent,
    checkedAt: state.checkedAt,
  };
}

/** The org the web app has selected, else the most recently joined one. */
export function pickOrg(organizations, currentOrgId) {
  if (!organizations?.length) return null;
  return organizations.find((o) => o.id === currentOrgId) || organizations[0];
}

/** Detections in `detections` whose id wasn't seen by the previous poll. */
export function unseenDetections(detections, seenIds) {
  const seen = new Set(seenIds);
  return detections.filter((d) => !seen.has(d.id));
}

export function detectionsUrl(slug) {
  return `${APP_URL}/org/${encodeURIComponent(slug)}/detections`;
}

async function currentOrg() {
  const { organizations } = await listOrganizations();
  if (!organizations?.length) return null;
  if (organizations.length === 1) return organizations[0];
  const { profile } = await getProfile();
  return pickOrg(organizations, profile?.current_org_id);
}

async function notificationsEnabled() {
  const { notificationsEnabled } = await chrome.storage.local.get('notificationsEnabled');
  return notificationsEnabled !== false;
}

async function notify(org, urgent) {
  if (!urgent.length || !(await notificationsEnabled())) return;
  const [first] = urgent;
  const title =
    urgent.length === 1
      ? `${first.severity === 'critical' ? 'Critical' : 'High'} detection in ${org.name}`
      : `${urgent.length} new high/critical detections in ${org.name}`;
  const message =
    urgent.length === 1 ? first.title : urgent.slice(0, 3).map((d) => `• ${d.title}`).join('\n');
  // One notification per org, replaced by the next poll's alert.
  await chrome.notifications.create(`${NOTIFICATION_PREFIX}${org.slug}`, {
    type: 'basic',
    iconUrl: chrome.runtime.getURL('icons/icon-128.png'),
    title,
    message,
  });
}

async function setTooltip(state) {
  const title = state?.org && state.newCount > 0
    ? `${DEFAULT_TITLE}: ${state.newCount} new detection${state.newCount === 1 ? '' : 's'} in ${state.org.name}`
    : DEFAULT_TITLE;
  await chrome.action.setTitle({ title }).catch(() => {});
}

async function runCheck() {
  if (!(await getAuthToken())) {
    await chrome.storage.local.remove(STATE_KEY);
    await setTooltip(null);
    return summary(null);
  }

  const previous = (await chrome.storage.local.get(STATE_KEY))[STATE_KEY] || null;
  let org;
  let page;
  try {
    org = await currentOrg();
    if (org) page = await listDetections(org.id, { status: 'new', limit: String(PAGE_SIZE) });
  } catch (err) {
    // Offline, API down, or token rejected: keep the last known state.
    console.warn('[ThreatCrush] Detection check failed:', err?.message || err);
    return { ...summary(previous), signedIn: true, error: 'Could not reach ThreatCrush.' };
  }

  if (!org) {
    const state = {
      org: null,
      newCount: 0,
      urgentCount: 0,
      urgentPartial: false,
      recent: [],
      seenIds: [],
      checkedAt: Date.now(),
    };
    await chrome.storage.local.set({ [STATE_KEY]: state });
    await setTooltip(state);
    return summary(state);
  }

  const detections = page.detections || [];
  // First poll for this org sets the baseline: what already exists shows in
  // the count, but only detections that arrive afterwards notify.
  const baseline = !previous || previous.org?.id !== org.id;
  const fresh = baseline ? [] : unseenDetections(detections, previous.seenIds);

  const state = {
    org: { id: org.id, slug: org.slug, name: org.name },
    newCount: page.total ?? detections.length,
    urgentCount: detections.filter((d) => ALERT_SEVERITIES.has(d.severity)).length,
    // More new detections exist than one page holds, so urgentCount is a floor.
    urgentPartial: (page.total ?? 0) > detections.length,
    recent: detections.slice(0, RECENT_SHOWN).map(({ id, title, severity, detected_at }) => ({
      id,
      title,
      severity,
      detected_at,
    })),
    seenIds: detections.map((d) => d.id),
    checkedAt: Date.now(),
  };
  await chrome.storage.local.set({ [STATE_KEY]: state });
  await setTooltip(state);
  await notify(state.org, fresh.filter((d) => ALERT_SEVERITIES.has(d.severity))).catch((err) =>
    console.warn('[ThreatCrush] Notification failed:', err?.message || err)
  );
  return summary(state);
}

let inFlight = null;

/**
 * Poll once and return the popup summary. Concurrent callers (alarm + popup)
 * share one poll so a detection can't notify twice.
 */
export function checkDetections() {
  inFlight ??= runCheck().finally(() => {
    inFlight = null;
  });
  return inFlight;
}

/** Open the org's detections page when an alert is clicked. Call at worker start-up. */
export function registerDetectionAlerts() {
  chrome.notifications.onClicked.addListener((id) => {
    if (!id.startsWith(NOTIFICATION_PREFIX)) return;
    chrome.tabs.create({ url: detectionsUrl(id.slice(NOTIFICATION_PREFIX.length)) });
    chrome.notifications.clear(id);
  });
}
