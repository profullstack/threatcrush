import React from 'react';
import { useEventsStore } from '../../store/events';

const APP_URL = import.meta.env.VITE_APP_URL || 'https://threatcrush.com';

const SEVERITY_DOTS = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-400',
  info: 'bg-gray-500',
};

function timeAgo(iso) {
  const minutes = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (!Number.isFinite(minutes)) return '';
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  return new Date(iso).toLocaleDateString();
}

/** The org's newest detections still marked new. */
export default function EventFeed() {
  const { alerts, loading } = useEventsStore();

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-xs text-gray-500">Loading detections...</div>
      </div>
    );
  }

  if (!alerts.org) return <div className="flex-1" />;

  if (alerts.recent.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center">
          <div className="text-2xl mb-1">🛡️</div>
          <div className="text-xs text-gray-500">No new detections</div>
        </div>
      </div>
    );
  }

  const detectionsUrl = `${APP_URL}/org/${encodeURIComponent(alerts.org.slug)}/detections`;

  return (
    <div className="flex-1 overflow-y-auto px-4 py-2">
      <div className="flex items-center justify-between mb-2">
        <div className="text-[10px] uppercase text-gray-500 font-semibold tracking-wider">New detections</div>
        <button
          onClick={() => chrome.tabs.create({ url: detectionsUrl })}
          className="text-[10px] text-gray-500 hover:text-[#00ff41] transition-colors"
        >
          View all
        </button>
      </div>
      <div className="space-y-1.5">
        {alerts.recent.map((d) => (
          <div
            key={d.id}
            className="flex items-start gap-2 p-2 bg-[#111] rounded-lg border border-[#222] hover:border-[#333] transition-colors"
          >
            <span
              className={`mt-1 w-2 h-2 rounded-full flex-shrink-0 ${SEVERITY_DOTS[d.severity] || SEVERITY_DOTS.info}`}
              title={d.severity}
            />
            <div className="flex-1 min-w-0">
              <div className="text-xs text-white truncate">{d.title}</div>
              <div className="text-[10px] text-gray-500">
                {d.severity} · {timeAgo(d.detected_at)}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
