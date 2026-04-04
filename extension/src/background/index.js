/**
 * ThreatCrush Background Service Worker
 *
 * Handles periodic security event checks, badge updates, and notifications.
 */

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
    const { authToken, serverUrl } = await chrome.storage.local.get([
      'authToken',
      'serverUrl',
    ]);

    if (!authToken) {
      // Not logged in, clear badge
      await updateBadge({ threats: 0, warnings: 0 });
      return;
    }

    // TODO: Replace with real API call when connected
    // For now, use demo data
    const stats = await getDemoStats();

    await updateBadge(stats);

    // Show notification for new threats
    if (stats.threats > 0) {
      const { notificationsEnabled } = await chrome.storage.local.get('notificationsEnabled');
      if (notificationsEnabled !== false) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon-128.png',
          title: 'ThreatCrush Alert',
          message: `${stats.threats} active threat${stats.threats > 1 ? 's' : ''} detected`,
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
 * Get demo stats (placeholder until real API is connected)
 */
async function getDemoStats() {
  return {
    threats: 0,
    warnings: 0,
    eventsToday: 12,
    modulesRunning: 3,
  };
}

/**
 * Handle messages from popup/options
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_STATS') {
    getDemoStats().then(sendResponse);
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
 * Scan a URL for security issues (placeholder)
 */
async function scanUrl(url) {
  // TODO: Real scanning logic
  return {
    url,
    status: 'secure',
    checks: {
      ssl: { status: 'pass', message: 'Valid SSL certificate' },
      headers: { status: 'pass', message: 'Security headers present' },
      securityTxt: { status: 'unknown', message: 'Not checked yet' },
    },
    scannedAt: new Date().toISOString(),
  };
}
