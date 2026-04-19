import React, { useEffect } from 'react';
import { useAuthStore } from '../store/auth';
import { useEventsStore } from '../store/events';
import StatusBadge from './components/StatusBadge';
import QuickActions from './components/QuickActions';
import EventFeed from './components/EventFeed';
import LoginForm from './components/LoginForm';

export default function App() {
  const { user, loading: authLoading, initialize } = useAuthStore();
  const { stats, fetchStats } = useEventsStore();

  useEffect(() => {
    initialize();
  }, [initialize]);

  useEffect(() => {
    if (user) {
      fetchStats();
    }
  }, [user, fetchStats]);

  if (authLoading) {
    return (
      <div className="flex items-center justify-center h-[520px]">
        <div className="animate-spin-slow w-8 h-8 border-2 border-[#00ff41] border-t-transparent rounded-full" />
      </div>
    );
  }

  if (!user) {
    return <LoginForm />;
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#222]">
        <div className="flex items-center gap-2">
          <span className="text-[#00ff41] text-lg font-bold font-mono">⛨</span>
          <span className="text-sm font-bold text-white">ThreatCrush</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500 truncate max-w-[140px]">{user.email}</span>
          <button
            onClick={() => useAuthStore.getState().logout()}
            className="text-xs text-gray-500 hover:text-[#00ff41] transition-colors"
          >
            Logout
          </button>
        </div>
      </div>

      {/* Status Badge */}
      <StatusBadge stats={stats} />

      {/* Quick Stats */}
      <div className="grid grid-cols-3 gap-2 px-4 py-2">
        <div className="bg-[#111] rounded-lg p-2 text-center border border-[#222]">
          <div className="text-lg font-bold text-[#00ff41]">{stats.eventsToday}</div>
          <div className="text-[10px] text-gray-500">Events Today</div>
        </div>
        <div className="bg-[#111] rounded-lg p-2 text-center border border-[#222]">
          <div className="text-lg font-bold text-yellow-500">{stats.threats}</div>
          <div className="text-[10px] text-gray-500">Active Threats</div>
        </div>
        <div className="bg-[#111] rounded-lg p-2 text-center border border-[#222]">
          <div className="text-lg font-bold text-blue-400">{stats.modulesRunning}</div>
          <div className="text-[10px] text-gray-500">Modules</div>
        </div>
      </div>

      {/* Recent Events */}
      <EventFeed />

      {/* Quick Actions */}
      <QuickActions />
    </div>
  );
}
