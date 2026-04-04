import React, { useState } from 'react';

const APP_URL = import.meta.env.VITE_APP_URL || 'https://threatcrush.com';

export default function QuickActions() {
  const [scanning, setScanning] = useState(false);

  async function handleScanSite() {
    setScanning(true);
    try {
      // Get current tab URL
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url) {
        const response = await chrome.runtime.sendMessage({
          type: 'SCAN_URL',
          url: tab.url,
        });
        console.log('[ThreatCrush] Scan result:', response);
        // TODO: Show scan results in UI
      }
    } catch (error) {
      console.error('[ThreatCrush] Scan failed:', error);
    } finally {
      setScanning(false);
    }
  }

  function openUrl(path) {
    chrome.tabs.create({ url: `${APP_URL}${path}` });
  }

  return (
    <div className="mt-auto px-4 py-3 border-t border-[#222] space-y-2">
      <button
        onClick={handleScanSite}
        disabled={scanning}
        className="w-full py-2 px-3 bg-[#00ff41] text-black font-semibold text-sm rounded-lg hover:bg-[#00e03a] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {scanning ? (
          <span className="flex items-center justify-center gap-2">
            <span className="animate-spin w-4 h-4 border-2 border-black border-t-transparent rounded-full" />
            Scanning...
          </span>
        ) : (
          '🔍 Scan This Site'
        )}
      </button>

      <div className="grid grid-cols-3 gap-2">
        <button
          onClick={() => openUrl('/account')}
          className="py-1.5 px-2 bg-[#111] border border-[#222] text-xs text-gray-400 rounded-lg hover:border-[#00ff41] hover:text-[#00ff41] transition-colors"
        >
          Dashboard
        </button>
        <button
          onClick={() => openUrl('/usage')}
          className="py-1.5 px-2 bg-[#111] border border-[#222] text-xs text-gray-400 rounded-lg hover:border-[#00ff41] hover:text-[#00ff41] transition-colors"
        >
          Alerts
        </button>
        <button
          onClick={() => openUrl('/store')}
          className="py-1.5 px-2 bg-[#111] border border-[#222] text-xs text-gray-400 rounded-lg hover:border-[#00ff41] hover:text-[#00ff41] transition-colors"
        >
          Modules
        </button>
      </div>
    </div>
  );
}
