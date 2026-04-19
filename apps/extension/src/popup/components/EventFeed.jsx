import React from 'react';
import { useEventsStore } from '../../store/events';

const EVENT_ICONS = {
  info: '🔵',
  warning: '🟡',
  threat: '🔴',
  scan: '🔍',
  module: '📦',
};

export default function EventFeed() {
  const { events, loading } = useEventsStore();

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-xs text-gray-500">Loading events...</div>
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center">
          <div className="text-2xl mb-1">🛡️</div>
          <div className="text-xs text-gray-500">No recent events</div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto px-4 py-2">
      <div className="text-[10px] uppercase text-gray-500 font-semibold mb-2 tracking-wider">
        Recent Events
      </div>
      <div className="space-y-1.5">
        {events.slice(0, 5).map((event) => (
          <div
            key={event.id}
            className="flex items-start gap-2 p-2 bg-[#111] rounded-lg border border-[#222] hover:border-[#333] transition-colors"
          >
            <span className="text-sm flex-shrink-0">{EVENT_ICONS[event.type] || '🔵'}</span>
            <div className="flex-1 min-w-0">
              <div className="text-xs text-white truncate">{event.title}</div>
              <div className="text-[10px] text-gray-500">{event.time}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
