import type { ThreatCrushConfig, AlertChannelConfig } from '../../types/config.js';
import type { ThreatEvent } from '../../types/events.js';
import type { EventBus } from '../event-bus.js';
import { smtpChannel, type SmtpConfig } from './smtp.js';
import { discordChannel, type DiscordConfig } from './discord.js';
import { pagerdutyChannel, type PagerDutyConfig } from './pagerduty.js';

type Channel = (event: ThreatEvent) => Promise<void>;

export class AlertDispatcher {
  private channels: Channel[] = [];
  private rateLimits = new Map<string, number[]>();

  constructor(private bus: EventBus, private config: ThreatCrushConfig) {
    this.bindChannels();
    bus.on('alert', (event) => { void this.dispatch(event); });
  }

  private bindChannels(): void {
    const alerts = this.config.alerts || {};
    for (const [name, raw] of Object.entries(alerts)) {
      const cfg = raw as AlertChannelConfig;
      if (!cfg.enabled) continue;
      if (name === 'webhook' && typeof cfg.url === 'string') {
        this.channels.push(webhookChannel(cfg.url, cfg.secret as string | undefined));
      }
      if (name === 'slack' && typeof cfg.webhook_url === 'string') {
        this.channels.push(slackChannel(cfg.webhook_url));
      }
      if (name === 'email' && typeof cfg.host === 'string' && typeof cfg.from === 'string') {
        this.channels.push(smtpChannel(cfg as unknown as SmtpConfig));
      }
      if (name === 'discord' && typeof cfg.webhook_url === 'string') {
        this.channels.push(discordChannel(cfg as unknown as DiscordConfig));
      }
      if (name === 'pagerduty' && typeof cfg.routing_key === 'string') {
        this.channels.push(pagerdutyChannel(cfg as unknown as PagerDutyConfig));
      }
    }
  }

  private checkRateLimit(channelIdx: number, maxPerHour: number = 60): boolean {
    const key = String(channelIdx);
    const now = Date.now();
    const hour = 3600_000;
    let timestamps = this.rateLimits.get(key) || [];
    timestamps = timestamps.filter(t => t > now - hour);
    if (timestamps.length >= maxPerHour) return false;
    timestamps.push(now);
    this.rateLimits.set(key, timestamps);
    return true;
  }

  private async dispatch(event: ThreatEvent): Promise<void> {
    await Promise.all(this.channels.map((ch, idx) => {
      if (!this.checkRateLimit(idx)) return Promise.resolve();
      return ch(event).catch(() => {});
    }));
  }
}

function webhookChannel(url: string, secret?: string): Channel {
  return async (event) => {
    const body = JSON.stringify({ event });
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (secret) headers['X-Threatcrush-Signature'] = secret;
    await fetch(url, { method: 'POST', headers, body });
  };
}

function slackChannel(webhookUrl: string): Channel {
  return async (event) => {
    const emoji = event.severity === 'critical' ? ':rotating_light:' : ':warning:';
    const text = `${emoji} *[${event.severity.toUpperCase()}]* \`${event.module}\` — ${event.message}${event.source_ip ? ` (from ${event.source_ip})` : ''}`;
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
  };
}
