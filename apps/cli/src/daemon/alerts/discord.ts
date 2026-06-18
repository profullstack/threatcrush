import type { ThreatEvent } from '../../types/events.js';

export interface DiscordConfig {
  webhook_url: string;
  min_severity?: 'low' | 'medium' | 'high' | 'critical';
}

const SEVERITY_RANK: Record<string, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

const SEVERITY_COLORS: Record<string, number> = {
  info: 0x2ecc71,     // green
  low: 0x3498db,      // blue
  medium: 0xf39c12,   // orange
  high: 0xe74c3c,     // red
  critical: 0x9b59b6, // purple
};

export function discordChannel(config: DiscordConfig): (event: ThreatEvent) => Promise<void> {
  return async (event) => {
    if (config.min_severity) {
      const eventRank = SEVERITY_RANK[event.severity] ?? 0;
      const minRank = SEVERITY_RANK[config.min_severity] ?? 0;
      if (eventRank < minRank) return;
    }

    const embed = {
      title: `${event.severity === 'critical' ? '🚨' : '⚠️'} [${event.severity.toUpperCase()}] ${event.module}`,
      description: event.message,
      color: SEVERITY_COLORS[event.severity] ?? 0xffffff,
      fields: [
        ...(event.source_ip ? [{ name: 'Source IP', value: `\`${event.source_ip}\``, inline: true }] : []),
        { name: 'Category', value: event.category, inline: true },
        { name: 'Time', value: event.timestamp.toISOString(), inline: true },
      ],
      footer: { text: 'ThreatCrush Security Alert' },
    };

    await fetch(config.webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [embed] }),
    });
  };
}
