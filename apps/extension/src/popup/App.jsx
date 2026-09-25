import React, { useEffect, useState } from 'react';
import { useAuthStore } from '../store/auth';
import { useEventsStore } from '../store/events';
import StatusBadge from './components/StatusBadge';
import QuickActions from './components/QuickActions';
import EventFeed from './components/EventFeed';
import LoginForm from './components/LoginForm';
import PageChecks from './components/PageChecks';

function Account() {
  const { user, loading: authLoading } = useAuthStore();
  const { stats, fetchStats } = useEventsStore();

  useEffect(() => {
    if (user) {
      fetchStats();
    }
  }, [user, fetchStats]);

  if (authLoading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="animate-spin-slow w-8 h-8 border-2 border-[#00ff41] border-t-transparent rounded-full" />
      </div>
    );
  }

  if (!user) {
    return <LoginForm />;
  }

  return (
    <div className="flex-1 flex flex-col min-h-0">
      <div className="flex items-center justify-between px-4 pt-2 gap-2">
        <span className="text-xs text-gray-500 truncate">{user.email}</span>
        <button
          onClick={() => useAuthStore.getState().logout()}
          className="text-xs text-gray-500 hover:text-[#00ff41] transition-colors"
        >
          Logout
        </button>
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

const VIEWS = [
  ['page', 'This page'],
  ['account', 'Account'],
];

export default function App() {
  const [view, setView] = useState('page');
  const initialize = useAuthStore((state) => state.initialize);

  useEffect(() => {
    initialize();
  }, [initialize]);

  return (
    <div className="flex flex-col h-[560px]">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#222]">
        <div className="flex items-center gap-2">
          <span className="text-[#00ff41] text-lg font-bold font-mono">⛨</span>
          <span className="text-sm font-bold text-white">ThreatCrush</span>
        </div>
        <div className="flex gap-1" role="tablist">
          {VIEWS.map(([id, label]) => (
            <button
              key={id}
              role="tab"
              aria-selected={view === id}
              onClick={() => setView(id)}
              className={`px-2 py-1 text-xs rounded-md transition-colors ${
                view === id ? 'bg-[#00ff41]/10 text-[#00ff41]' : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {view === 'page' ? <PageChecks /> : <Account />}
    </div>
  );
}
