import React, { useState, useEffect } from 'react';
import { PAGE_ORIGINS } from '../lib/page-checks.js';

// The scan button posts to the URL baked in at build time (see lib/api.js).
const SCAN_API_URL = import.meta.env.VITE_APP_URL || 'https://threatcrush.com';

const DEFAULT_SETTINGS = {
  serverUrl: 'https://threatcrush.com',
  licenseKey: '',
  notificationsEnabled: true,
  autoCheck: true,
  scanInterval: 5,
};

const MIN_SCAN_INTERVAL = 1;
const MAX_SCAN_INTERVAL = 60;
const EVENT_CHECK_ALARM = 'threatcrush-event-check';

function normalizeScanInterval(value) {
  const parsed = Number.parseInt(value, 10);

  if (!Number.isFinite(parsed)) {
    return DEFAULT_SETTINGS.scanInterval;
  }

  return Math.min(MAX_SCAN_INTERVAL, Math.max(MIN_SCAN_INTERVAL, parsed));
}

export default function App() {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [saved, setSaved] = useState(false);
  const [siteAccess, setSiteAccess] = useState(false);

  useEffect(() => {
    // Load settings from storage
    chrome.storage.local.get(Object.keys(DEFAULT_SETTINGS), (stored) => {
      setSettings({ ...DEFAULT_SETTINGS, ...stored });
    });
    chrome.permissions.contains({ origins: [...PAGE_ORIGINS] }).then(setSiteAccess);
  }, []);

  function toggleSiteAccess() {
    // Permission requests must happen directly in the click handler (Firefox).
    const change = siteAccess
      ? chrome.permissions.remove({ origins: [...PAGE_ORIGINS] }).then((removed) => !removed)
      : chrome.permissions.request({ origins: [...PAGE_ORIGINS] });
    change.then(setSiteAccess);
  }

  async function handleSave(e) {
    e.preventDefault();
    const nextSettings = {
      ...settings,
      scanInterval: normalizeScanInterval(settings.scanInterval),
    };

    await chrome.storage.local.set(nextSettings);
    await chrome.alarms.create(EVENT_CHECK_ALARM, {
      periodInMinutes: nextSettings.scanInterval,
    });
    setSettings(nextSettings);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  function updateSetting(key, value) {
    setSettings((prev) => ({ ...prev, [key]: value }));
  }

  return (
    <div className="max-w-xl mx-auto p-8">
      {/* Header */}
      <div className="flex items-center gap-3 mb-8">
        <span className="text-3xl">⛨</span>
        <div>
          <h1 className="text-xl font-bold text-white font-mono">ThreatCrush</h1>
          <p className="text-xs text-gray-500">Extension Settings</p>
        </div>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* API Settings */}
        <section className="bg-[#111] rounded-lg border border-[#222] p-5">
          <h2 className="text-sm font-semibold text-[#00ff41] mb-4">API Settings</h2>

          <div className="space-y-3">
            <div>
              <label htmlFor="server-url" className="block text-xs text-gray-400 mb-1">Server URL</label>
              <input
                id="server-url"
                type="url"
                value={settings.serverUrl}
                onChange={(e) => updateSetting('serverUrl', e.target.value)}
                className="w-full px-3 py-2 bg-[#0a0a0a] border border-[#222] rounded-lg text-sm text-white focus:outline-none focus:border-[#00ff41] transition-colors"
              />
            </div>

            <div>
              <label htmlFor="license-key" className="block text-xs text-gray-400 mb-1">License Key</label>
              <input
                id="license-key"
                type="password"
                value={settings.licenseKey}
                onChange={(e) => updateSetting('licenseKey', e.target.value)}
                placeholder="tc_xxxxxxxxxxxxxxxx"
                className="w-full px-3 py-2 bg-[#0a0a0a] border border-[#222] rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-[#00ff41] transition-colors"
              />
            </div>
          </div>
        </section>

        {/* Page checks */}
        <section className="bg-[#111] rounded-lg border border-[#222] p-5">
          <h2 className="text-sm font-semibold text-[#00ff41] mb-4">Page checks</h2>

          <div className="space-y-4">
            <div className="flex items-center justify-between gap-4">
              <div className="text-sm text-gray-300">
                Site access{' '}
                <span className={siteAccess ? 'text-[#00ff41]' : 'text-yellow-400'}>
                  {siteAccess ? 'granted' : 'not granted'}
                </span>
                <p className="text-xs text-gray-500 mt-1">
                  Needed to read a page's response headers and cookie flags. Without it, only the HTTPS, form and
                  mixed-content checks run, and only when you open the popup.
                </p>
              </div>
              <button
                type="button"
                onClick={toggleSiteAccess}
                className="flex-shrink-0 px-3 py-1.5 border border-[#333] text-xs text-gray-300 rounded-lg hover:border-[#00ff41] hover:text-[#00ff41] transition-colors"
              >
                {siteAccess ? 'Revoke' : 'Grant'}
              </button>
            </div>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={settings.autoCheck}
                onChange={(e) => updateSetting('autoCheck', e.target.checked)}
                className="w-4 h-4 accent-[#00ff41]"
              />
              <span className="text-sm text-gray-300">
                Check every page as it loads and show the result on the toolbar badge
              </span>
            </label>
          </div>
        </section>

        {/* Privacy */}
        <section className="bg-[#111] rounded-lg border border-[#222] p-5" aria-labelledby="privacy-heading">
          <h2 id="privacy-heading" className="text-sm font-semibold text-[#00ff41] mb-3">Privacy</h2>
          <div className="space-y-2 text-xs text-gray-400 leading-relaxed">
            <p>
              Page checks run entirely in your browser. The extension reads the page's security headers, cookie
              names and flags (never cookie values), form targets and subresource URLs, and keeps them only for the
              open tab. Nothing about the pages you visit is sent to ThreatCrush or anyone else.
            </p>
            <p>
              The one exception is the <span className="text-gray-200">Scan with ThreatCrush</span> button in the
              popup. When you click it, the page's address without its query string or fragment is sent to{' '}
              {SCAN_API_URL}, whose servers fetch that page and grade its headers.
            </p>
          </div>
        </section>

        {/* Notification Settings */}
        <section className="bg-[#111] rounded-lg border border-[#222] p-5">
          <h2 className="text-sm font-semibold text-[#00ff41] mb-4">Account alerts</h2>

          <div className="space-y-3">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={settings.notificationsEnabled}
                onChange={(e) => updateSetting('notificationsEnabled', e.target.checked)}
                className="w-4 h-4 accent-[#00ff41]"
              />
              <span className="text-sm text-gray-300">
                Browser notifications for new threats
              </span>
            </label>

            <div>
              <label htmlFor="scan-interval" className="block text-xs text-gray-400 mb-1">
                Event check interval (minutes)
              </label>
              <input
                id="scan-interval"
                type="number"
                min="1"
                max="60"
                value={settings.scanInterval}
                onChange={(e) => updateSetting('scanInterval', e.target.value)}
                className="w-24 px-3 py-2 bg-[#0a0a0a] border border-[#222] rounded-lg text-sm text-white focus:outline-none focus:border-[#00ff41] transition-colors"
              />
            </div>
          </div>
        </section>

        {/* Save */}
        <div className="flex items-center gap-3">
          <button
            type="submit"
            className="px-6 py-2 bg-[#00ff41] text-black font-semibold text-sm rounded-lg hover:bg-[#00e03a] transition-colors"
          >
            Save Settings
          </button>
          {saved && (
            <span className="text-sm text-[#00ff41] animate-pulse">✓ Saved</span>
          )}
        </div>
      </form>

      {/* Version */}
      <div className="mt-8 text-center text-xs text-gray-600">
        ThreatCrush Extension v{import.meta.env.VITE_APP_VERSION || '0.1.10'}
      </div>
    </div>
  );
}
