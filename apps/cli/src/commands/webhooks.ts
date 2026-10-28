import chalk from 'chalk';
import { cloudFetch, hasSession, readCliConfig } from '../core/cli-config.js';

// `threatcrush webhooks` — the current org's webhook endpoints, through
// /api/v1/webhooks (the same API the web app's Settings -> Alerts and MCP use).
// Deliveries are Standard Webhooks signed, retried for about three days, logged.

export interface WebhookEndpoint {
  id: string;
  url: string;
  events: string[];
  description: string;
  enabled: boolean;
  failures: number;
  disabled_reason: string | null;
}

interface WebhookDelivery {
  id: string;
  event_type: string;
  status: string;
  attempts: number;
  last_status: number | null;
  last_error: string | null;
  created_at: string;
}

function orgOrExplain(): string | null {
  if (!hasSession()) {
    console.log(chalk.red(`  Not signed in. Run ${chalk.white('threatcrush login')} first.\n`));
    process.exitCode = 1;
    return null;
  }
  const org = readCliConfig().current_org_id;
  if (!org) {
    console.log(chalk.red(`  No current org. Run ${chalk.white('threatcrush orgs use <slug>')}.\n`));
    process.exitCode = 1;
    return null;
  }
  return org;
}

async function api<T>(path: string, init?: { method?: string; body?: string }): Promise<T | null> {
  const org = orgOrExplain();
  if (!org) return null;
  const res = await cloudFetch(`/api/v1/webhooks${path}?org_id=${encodeURIComponent(org)}`, init);
  const data = (await res.json().catch(() => ({}))) as T & { error?: string };
  if (!res.ok) {
    console.log(chalk.red(`  ${data.error || `HTTP ${res.status}`}${res.status === 401 ? ` — run ${chalk.white('threatcrush login')}` : ''}\n`));
    process.exitCode = 1;
    return null;
  }
  return data;
}

const json = (v: unknown) => console.log(JSON.stringify(v, null, 2));

function printSecret(id: string, secret: string) {
  console.log(chalk.green(`\n  Signing secret for ${id} (shown once, keep it in your vault):`));
  console.log(`  ${chalk.white(secret)}`);
  console.log(chalk.dim('  Verify the webhook-signature header with any Standard Webhooks library.\n'));
}

export async function webhooksListCommand(opts: { json?: boolean } = {}): Promise<void> {
  const data = await api<{ endpoints: WebhookEndpoint[]; event_types: string[] }>('');
  if (!data) return;
  if (opts.json) return json(data);
  console.log(chalk.bold('\n  Webhook endpoints') + chalk.dim(`  events: ${data.event_types.join(', ')}\n`));
  if (!data.endpoints.length) {
    console.log(chalk.dim(`  None yet. Add one: threatcrush webhooks add <https-url> [--events detection.created,findings.*]\n`));
    return;
  }
  for (const e of data.endpoints) {
    const state = e.enabled ? chalk.green('on ') : chalk.gray('off');
    console.log(`  ${chalk.gray(e.id)} ${state} ${e.url}`);
    console.log(chalk.dim(`      ${e.events.join(', ')}${e.description ? ` · ${e.description}` : ''}${e.failures ? ` · ${e.failures} failures in a row` : ''}${e.disabled_reason ? ` · ${e.disabled_reason}` : ''}`));
  }
  console.log();
}

export async function webhooksAddCommand(url: string, opts: { events?: string; description?: string; json?: boolean }): Promise<void> {
  const body = {
    url,
    ...(opts.events ? { events: opts.events.split(',').map((s) => s.trim()).filter(Boolean) } : {}),
    ...(opts.description ? { description: opts.description } : {}),
  };
  const data = await api<{ endpoint: WebhookEndpoint; secret: string }>('', { method: 'POST', body: JSON.stringify(body) });
  if (!data) return;
  if (opts.json) return json(data);
  console.log(chalk.green(`  Added ${data.endpoint.id} → ${data.endpoint.url} (${data.endpoint.events.join(', ')})`));
  printSecret(data.endpoint.id, data.secret);
}

export async function webhooksUpdateCommand(id: string, opts: { url?: string; events?: string; description?: string; enable?: boolean; disable?: boolean; json?: boolean }): Promise<void> {
  const patch: Record<string, unknown> = {};
  if (opts.url) patch.url = opts.url;
  if (opts.events) patch.events = opts.events.split(',').map((s) => s.trim()).filter(Boolean);
  if (opts.description !== undefined) patch.description = opts.description;
  if (opts.enable) patch.enabled = true;
  if (opts.disable) patch.enabled = false;
  const data = await api<WebhookEndpoint>(`/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(patch) });
  if (!data) return;
  if (opts.json) return json(data);
  console.log(chalk.green(`  Updated ${data.id}: ${data.enabled ? 'on' : 'off'}, ${data.url}, ${data.events.join(', ')}\n`));
}

export async function webhooksRemoveCommand(id: string): Promise<void> {
  if (await api(`/${encodeURIComponent(id)}`, { method: 'DELETE' })) console.log(chalk.green(`  Removed ${id}\n`));
}

export async function webhooksTestCommand(id: string): Promise<void> {
  const r = await api<{ ok: boolean; status: number | null; error: string | null }>(`/${encodeURIComponent(id)}/test`, { method: 'POST' });
  if (!r) return;
  if (r.ok) console.log(chalk.green(`  Test delivered (HTTP ${r.status})\n`));
  else {
    console.log(chalk.red(`  Test failed: ${r.error ?? `HTTP ${r.status}`}\n`));
    process.exitCode = 1;
  }
}

export async function webhooksSecretCommand(id: string, opts: { rotate?: boolean }): Promise<void> {
  const r = opts.rotate
    ? await api<{ secret: string }>(`/${encodeURIComponent(id)}/rotate`, { method: 'POST' })
    : await api<{ secret: string }>(`/${encodeURIComponent(id)}/secret`);
  if (r) printSecret(id, r.secret);
}

export async function webhooksDeliveriesCommand(id: string | undefined, opts: { limit?: string; json?: boolean }): Promise<void> {
  const limit = Math.min(200, Number(opts.limit) || 20);
  const path = id ? `/${encodeURIComponent(id)}/deliveries` : '/deliveries';
  const org = readCliConfig().current_org_id;
  if (!org) return void orgOrExplain();
  const res = await cloudFetch(`/api/v1/webhooks${path}?org_id=${encodeURIComponent(org)}&limit=${limit}`);
  const data = (await res.json().catch(() => ({}))) as { deliveries?: WebhookDelivery[]; error?: string };
  if (!res.ok) {
    console.log(chalk.red(`  ${data.error || `HTTP ${res.status}`}\n`));
    process.exitCode = 1;
    return;
  }
  if (opts.json) return json(data);
  const rows = data.deliveries ?? [];
  if (!rows.length) return void console.log(chalk.dim('  No deliveries yet.\n'));
  for (const d of rows) {
    const color = d.status === 'delivered' ? chalk.green : d.status === 'failed' ? chalk.red : chalk.yellow;
    console.log(`  ${chalk.gray(d.created_at.slice(0, 19).replace('T', ' '))} ${color(d.status.padEnd(9))} ${d.event_type.padEnd(20)} ${d.attempts} tries${d.last_status ? `, HTTP ${d.last_status}` : ''}${d.last_error ? chalk.dim(` · ${d.last_error}`) : ''}`);
  }
  console.log(chalk.dim(`\n  Resend one: threatcrush webhooks retry <delivery-id>\n`));
}

export async function webhooksRetryCommand(deliveryId: string): Promise<void> {
  if (await api(`/deliveries/${encodeURIComponent(deliveryId)}/retry`, { method: 'POST' })) console.log(chalk.green(`  Queued ${deliveryId} again\n`));
}
