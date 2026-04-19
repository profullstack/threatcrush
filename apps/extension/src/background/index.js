/**
 * ThreatCrush Background Service Worker
 *
 * Handles periodic security event checks, badge updates, and notifications.
 */

import { getUsageStats, scanUrl as apiScanUrl } from '../lib/api.js';

const ALARM_NAME = 'threatcrush-event-check';
const CHECK_INTERVAL_MINUTES = 5;

// Badge colors
const BADGE_COLORS = {
  secure: '#00ff41',
  warning: '#f59e0b',
  threat: '#ef4444',
};

/**
 * Initialize the extension on install
 */
chrome.runtime.onInstalled.addListener(async () => {
  console.log('[ThreatCrush] Extension installed');

  // Set up periodic alarm for event checking
  await chrome.alarms.create(ALARM_NAME, {
    periodInMinutes: CHECK_INTERVAL_MINUTES,
  });

  // Set initial badge
  await updateBadge({ threats: 0, warnings: 0 });
});

/**
 * Handle alarm events
 */
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === ALARM_NAME) {
    await checkForEvents();
  }
});

/**
 * Check for new security events
 */
async function checkForEvents() {
  try {
    // Get stored auth token
    const { authToken } = await chrome.storage.local.get(['authToken']);

    if (!authToken) {
      // Not logged in, clear badge
      await updateBadge({ threats: 0, warnings: 0 });
      return;
    }

    // Fetch real usage stats from the API
    const usage = await getUsageStats(authToken);

    const threats = usage.threats || 0;
    const warnings = usage.warnings || 0;

    await updateBadge({ threats, warnings });

    // Show notification for new threats
    if (threats > 0) {
      const { notificationsEnabled } = await chrome.storage.local.get('notificationsEnabled');
      if (notificationsEnabled !== false) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon-128.png',
          title: 'ThreatCrush Alert',
          message: `${threats} active threat${threats > 1 ? 's' : ''} detected`,
        });
      }
    }
  } catch (error) {
    console.error('[ThreatCrush] Event check failed:', error);
  }
}

/**
 * Update the extension badge
 */
async function updateBadge({ threats, warnings }) {
  if (threats > 0) {
    await chrome.action.setBadgeText({ text: String(threats) });
    await chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS.threat });
  } else if (warnings > 0) {
    await chrome.action.setBadgeText({ text: String(warnings) });
    await chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS.warning });
  } else {
    await chrome.action.setBadgeText({ text: '' });
    await chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS.secure });
  }
}

/**
 * Handle messages from popup/options
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_STATS') {
    chrome.storage.local.get(['authToken']).then(async ({ authToken }) => {
      if (!authToken) {
        sendResponse({ threats: 0, warnings: 0, eventsToday: 0, modulesRunning: 0 });
        return;
      }
      try {
        const usage = await getUsageStats(authToken);
        sendResponse({
          threats: usage.threats || 0,
          warnings: usage.warnings || 0,
          eventsToday: usage.today_requests || usage.events_today || 0,
          modulesRunning: 0,
        });
      } catch (err) {
        console.error('[ThreatCrush] GET_STATS failed:', err);
        sendResponse({ threats: 0, warnings: 0, eventsToday: 0, modulesRunning: 0 });
      }
    });
    return true; // async response
  }

  if (message.type === 'CHECK_NOW') {
    checkForEvents().then(() => sendResponse({ ok: true }));
    return true;
  }

  if (message.type === 'SCAN_URL') {
    scanUrl(message.url).then(sendResponse);
    return true;
  }
});

/**
 * Scan a URL for security issues using the real API
 */
async function scanUrl(url) {
  const { authToken } = await chrome.storage.local.get(['authToken']);
  if (!authToken) {
    return { url, status: 'unauthenticated', error: 'Not logged in' };
  }
  try {
    return await apiScanUrl(url, authToken);
  } catch (err) {
    console.error('[ThreatCrush] Scan failed:', err);
    return { url, status: 'error', error: err.message };
  }
}
