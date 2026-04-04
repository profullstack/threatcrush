import React from 'react';

const STATUS_CONFIG = {
  secure: {
    icon: '✓',
    label: 'Secure',
    color: 'text-[#00ff41]',
    bgColor: 'bg-[#00ff41]/10',
    borderColor: 'border-[#00ff41]/30',
  },
  warning: {
    icon: '⚠',
    label: 'Warnings',
    color: 'text-yellow-500',
    bgColor: 'bg-yellow-500/10',
    borderColor: 'border-yellow-500/30',
  },
  threat: {
    icon: '✗',
    label: 'Threats Detected',
    color: 'text-red-500',
    bgColor: 'bg-red-500/10',
    borderColor: 'border-red-500/30',
  },
};

function getStatus(stats) {
  if (stats.threats > 0) return 'threat';
  if (stats.warnings > 0) return 'warning';
  return 'secure';
}

export default function StatusBadge({ stats }) {
  const status = getStatus(stats);
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
          <div className="text-xs text-gray-500">
            {status === 'secure' && 'No active threats detected'}
            {status === 'warning' && `${stats.warnings} warning${stats.warnings > 1 ? 's' : ''} need attention`}
            {status === 'threat' && `${stats.threats} active threat${stats.threats > 1 ? 's' : ''} detected`}
          </div>
        </div>
      </div>
    </div>
  );
}
