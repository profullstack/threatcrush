/**
 * ThreatCrush Background Service Worker
 *
 * Polls the signed-in account for new detections (./detections.js), raises
 * notifications, and runs the local checks on the page in each tab
 * (./page-checks.js).
 *
 * The toolbar badge belongs to page checks: it is set per tab for the page on
 * screen. The account's detection count goes in the popup, the toolbar
 * tooltip and notifications instead, so one badge never means two things.
 */

import { scanUrl as apiScanUrl } from '../lib/api.js';
import { scanTargetUrl } from '../lib/page-checks.js';
import { checkDetections, registerDetectionAlerts } from './detections.js';
import { checkTab, registerPageChecks } from './page-checks.js';

registerPageChecks();
registerDetectionAlerts();

const ALARM_NAME = 'threatcrush-event-check';
const DEFAULT_INTERVAL_MINUTES = 5;

chrome.runtime.onInstalled.addListener(async () => {
  // Keep the interval chosen in Options across updates.
  const { scanInterval } = await chrome.storage.local.get('scanInterval');
  await chrome.alarms.create(ALARM_NAME, {
    periodInMinutes: scanInterval || DEFAULT_INTERVAL_MINUTES,
  });
  await checkDetections();
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === ALARM_NAME) {
    await checkDetections();
  }
});

/**
 * Handle messages from popup/options
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_STATS') {
    checkDetections().then(sendResponse);
    return true; // async response
  }

  if (message.type === 'PAGE_CHECKS') {
    checkTab(message.tabId)
      .then(sendResponse)
      .catch((err) => sendResponse({ supported: false, error: err?.message || String(err), checks: [] }));
    return true;
  }

  if (message.type === 'SCAN_URL') {
    scanUrl(message.url).then(sendResponse);
    return true;
  }
});

/**
 * Server-side scan of a URL. Only runs when the user clicks "Scan with
 * ThreatCrush". Only the origin and path are sent; the query string and
 * fragment are dropped. The endpoint is public, so no sign-in is needed.
 */
async function scanUrl(url) {
  try {
    return await apiScanUrl(scanTargetUrl(url));
  } catch (err) {
    console.error('[ThreatCrush] Scan failed:', err);
    return { url, error: err.message };
  }
}
