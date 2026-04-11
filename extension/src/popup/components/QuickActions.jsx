import React, { useState } from 'react';

const APP_URL = import.meta.env.VITE_APP_URL || 'https://threatcrush.com';

const SEVERITY_COLORS = {
  critical: 'text-red-400',
  high: 'text-red-300',
  medium: 'text-yellow-300',
  low: 'text-cyan-300',
  info: 'text-green-300',
};

const STATUS_COLORS = {
  secure: 'text-green-400',
  warning: 'text-yellow-400',
  threat: 'text-red-400',
  error: 'text-red-300',
  unauthenticated: 'text-gray-400',
};

export default function QuickActions() {
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  async function handleScanSite() {
    setScanning(true);
    setScanResult(null);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url) {
        const response = await chrome.runtime.sendMessage({
          type: 'SCAN_URL',
          url: tab.url,
        });
        setScanResult(response);
      }
    } catch (error) {
      console.error('[ThreatCrush] Scan failed:', error);
      setScanResult({ status: 'error', error: error.message });
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

      {scanResult && (
        <div className="bg-[#111] border border-[#333] rounded-lg p-2 text-xs space-y-1">
          <div className={STATUS_COLORS[scanResult.status] || 'text-gray-300'}>
            Status: {scanResult.status}
          </div>
          {scanResult.grade && (
            <div className="text-gray-300">Grade: <span className="text-white font-bold">{scanResult.grade}</span></div>
          )}
          {scanResult.score !== undefined && (
            <div className="text-gray-300">Score: <span className="text-white">{scanResult.score}/100</span></div>
          )}
          {scanResult.checks && Object.entries(scanResult.checks).map(([key, check]) => (
            <div key={key} className="flex justify-between">
              <span className="text-gray-400">{key}</span>
              <span className={SEVERITY_COLORS[check.status] || 'text-gray-300'}>{check.status}</span>
            </div>
          ))}
          {scanResult.error && (
            <div className="text-red-400">{scanResult.error}</div>
          )}
        </div>
      )}

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
