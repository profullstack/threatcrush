import React, { useState, useEffect } from 'react';

const DEFAULT_SETTINGS = {
  serverUrl: 'https://threatcrush.com',
  licenseKey: '',
  notificationsEnabled: true,
  autoScan: false,
  scanInterval: 5,
};

export default function App() {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    // Load settings from storage
    chrome.storage.local.get(Object.keys(DEFAULT_SETTINGS), (stored) => {
      setSettings({ ...DEFAULT_SETTINGS, ...stored });
    });
  }, []);

  async function handleSave(e) {
    e.preventDefault();
    await chrome.storage.local.set(settings);
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
              <label className="block text-xs text-gray-400 mb-1">Server URL</label>
              <input
                type="url"
                value={settings.serverUrl}
                onChange={(e) => updateSetting('serverUrl', e.target.value)}
                className="w-full px-3 py-2 bg-[#0a0a0a] border border-[#222] rounded-lg text-sm text-white focus:outline-none focus:border-[#00ff41] transition-colors"
              />
            </div>

            <div>
              <label className="block text-xs text-gray-400 mb-1">License Key</label>
              <input
                type="password"
                value={settings.licenseKey}
                onChange={(e) => updateSetting('licenseKey', e.target.value)}
                placeholder="tc_xxxxxxxxxxxxxxxx"
                className="w-full px-3 py-2 bg-[#0a0a0a] border border-[#222] rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-[#00ff41] transition-colors"
              />
            </div>
          </div>
        </section>

        {/* Notification Settings */}
        <section className="bg-[#111] rounded-lg border border-[#222] p-5">
          <h2 className="text-sm font-semibold text-[#00ff41] mb-4">Notifications</h2>

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
        </section>

        {/* Auto-Scan Settings */}
        <section className="bg-[#111] rounded-lg border border-[#222] p-5">
          <h2 className="text-sm font-semibold text-[#00ff41] mb-4">Auto-Scan</h2>

          <div className="space-y-3">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={settings.autoScan}
                onChange={(e) => updateSetting('autoScan', e.target.checked)}
                className="w-4 h-4 accent-[#00ff41]"
              />
              <span className="text-sm text-gray-300">
                Automatically scan every new page
              </span>
            </label>

            <div>
              <label className="block text-xs text-gray-400 mb-1">
                Event check interval (minutes)
              </label>
              <input
                type="number"
                min="1"
                max="60"
                value={settings.scanInterval}
                onChange={(e) => updateSetting('scanInterval', parseInt(e.target.value, 10))}
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
