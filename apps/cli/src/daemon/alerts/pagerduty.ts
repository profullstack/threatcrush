import type { ThreatEvent } from '../../types/events.js';

export interface PagerDutyConfig {
  routing_key: string;
  min_severity?: 'low' | 'medium' | 'high' | 'critical';
}

const SEVERITY_RANK: Record<string, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

// Map ThreatCrush severity to PagerDuty severity
const PD_SEVERITY: Record<string, string> = {
  info: 'info',
  low: 'info',
  medium: 'warning',
  high: 'error',
  critical: 'critical',
};

export function pagerdutyChannel(config: PagerDutyConfig): (event: ThreatEvent) => Promise<void> {
  return async (event) => {
    if (config.min_severity) {
      const eventRank = SEVERITY_RANK[event.severity] ?? 0;
      const minRank = SEVERITY_RANK[config.min_severity] ?? 0;
      if (eventRank < minRank) return;
    }

    const payload = {
      routing_key: config.routing_key,
      event_action: 'trigger',
      payload: {
        summary: `[${event.severity.toUpperCase()}] ${event.module}: ${event.message}`,
        source: 'threatcrush',
        severity: PD_SEVERITY[event.severity] || 'warning',
        timestamp: event.timestamp.toISOString(),
        custom_details: {
          module: event.module,
          category: event.category,
          source_ip: event.source_ip,
          details: event.details,
        },
      },
    };

    await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  };
}
