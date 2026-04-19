import type { ThreatEvent } from '../../types/events.js';

type Mailer = {
  sendMail: (opts: Record<string, unknown>) => Promise<unknown>;
};

let transporter: Mailer | null = null;
// Lazy-load nodemailer so the CLI build doesn't pull it in when alerts are off.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let nodemailer: any = null;

export interface SmtpConfig {
  host?: string;
  port?: number;
  secure?: boolean;
  user?: string;
  pass?: string;
  from?: string;
  to?: string[] | string;
  min_severity?: 'low' | 'medium' | 'high' | 'critical';
}

const SEVERITY_RANK: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

async function ensureTransporter(config: SmtpConfig): Promise<Mailer | null> {
  if (!config.host || !config.from) return null;
  if (transporter) return transporter;

  if (!nodemailer) {
    try {
      nodemailer = await import('nodemailer');
    } catch {
      return null;
    }
  }

  transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port ?? 587,
    secure: config.secure ?? false,
    auth: config.user && config.pass ? { user: config.user, pass: config.pass } : undefined,
  });
  return transporter;
}

function meetsSeverity(event: ThreatEvent, min?: SmtpConfig['min_severity']): boolean {
  if (!min) return true;
  return (SEVERITY_RANK[event.severity] ?? 0) >= (SEVERITY_RANK[min] ?? 0);
}

function renderBody(event: ThreatEvent): { text: string; html: string } {
  const ts = event.timestamp.toISOString();
  const ip = event.source_ip ? `\nSource IP: ${event.source_ip}` : '';
  const text =
    `[${event.severity.toUpperCase()}] ${event.module}\n\n` +
    `${event.message}${ip}\n\n` +
    `When: ${ts}\nCategory: ${event.category}`;
  const html =
    `<div style="font-family:system-ui,sans-serif;line-height:1.5">` +
    `<h2 style="margin:0 0 8px">⚠ ${event.severity.toUpperCase()} — ${event.module}</h2>` +
    `<p>${event.message}</p>` +
    (event.source_ip ? `<p><strong>Source IP:</strong> <code>${event.source_ip}</code></p>` : '') +
    `<p style="color:#888;margin-top:16px"><small>${ts} · ${event.category}</small></p>` +
    `</div>`;
  return { text, html };
}

export function smtpChannel(config: SmtpConfig): (event: ThreatEvent) => Promise<void> {
  return async (event) => {
    if (!meetsSeverity(event, config.min_severity)) return;
    const t = await ensureTransporter(config);
    if (!t) return;

    const to = Array.isArray(config.to) ? config.to.join(', ') : config.to;
    if (!to) return;

    const { text, html } = renderBody(event);
    await t.sendMail({
      from: config.from,
      to,
      subject: `[ThreatCrush ${event.severity}] ${event.module} — ${event.message.slice(0, 60)}`,
      text,
      html,
    });
  };
}
