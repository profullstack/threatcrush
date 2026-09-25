import React from 'react';

const APP_URL = import.meta.env.VITE_APP_URL || 'https://threatcrush.com';

export default function QuickActions() {
  function openUrl(path) {
    chrome.tabs.create({ url: `${APP_URL}${path}` });
  }

  return (
    <div className="mt-auto px-4 py-3 border-t border-[#222]">
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
