import type { ThreatCrushConfig, AlertChannelConfig } from '../../types/config.js';
import type { ThreatEvent } from '../../types/events.js';
import type { EventBus } from '../event-bus.js';
import { smtpChannel, type SmtpConfig } from './smtp.js';

type Channel = (event: ThreatEvent) => Promise<void>;

export class AlertDispatcher {
  private channels: Channel[] = [];

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
    }
  }

  private async dispatch(event: ThreatEvent): Promise<void> {
    await Promise.all(this.channels.map((ch) => ch(event).catch(() => {})));
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
