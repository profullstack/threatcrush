import React from 'react';

const STATUS_CONFIG = {
  secure: {
    icon: '✓',
    label: 'No new detections',
    color: 'text-[#00ff41]',
    bgColor: 'bg-[#00ff41]/10',
    borderColor: 'border-[#00ff41]/30',
  },
  warning: {
    icon: '⚠',
    label: 'New detections',
    color: 'text-yellow-500',
    bgColor: 'bg-yellow-500/10',
    borderColor: 'border-yellow-500/30',
  },
  threat: {
    icon: '✗',
    label: 'High/critical detections',
    color: 'text-red-500',
    bgColor: 'bg-red-500/10',
    borderColor: 'border-red-500/30',
  },
  none: {
    icon: '–',
    label: 'No organization',
    color: 'text-gray-400',
    bgColor: 'bg-[#111]',
    borderColor: 'border-[#222]',
  },
};

function getStatus(alerts) {
  if (!alerts.org) return 'none';
  if (alerts.urgentCount > 0) return 'threat';
  if (alerts.newCount > 0) return 'warning';
  return 'secure';
}

function detail(status, alerts) {
  if (status === 'none') return 'Create or join an organization on ThreatCrush to get alerts from your servers.';
  const where = `in ${alerts.org.name}`;
  if (status === 'secure') return `Nothing new ${where}`;
  return `${alerts.newCount} new detection${alerts.newCount === 1 ? '' : 's'} ${where}`;
}

export default function StatusBadge({ alerts }) {
  const status = getStatus(alerts);
  const config = STATUS_CONFIG[status];

  return (
    <div className={`mx-4 mt-3 mb-1 p-3 rounded-lg border ${config.bgColor} ${config.borderColor}`}>
      <div className="flex items-center gap-2">
        <div className={`text-2xl ${config.color}`}>
          <span className="inline-block w-8 h-8 rounded-full border-2 border-current flex items-center justify-center text-sm font-bold">
            {config.icon}
          </span>
        </div>
        <div>
          <div className={`text-sm font-semibold ${config.color}`}>{config.label}</div>
          <div className="text-xs text-gray-500">{detail(status, alerts)}</div>
          {alerts.error && <div className="text-xs text-yellow-500">{alerts.error}</div>}
        </div>
      </div>
    </div>
  );
}
