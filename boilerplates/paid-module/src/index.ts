/**
 * Paid Feed Example — license-gated ThreatCrush module.
 *
 * On `init`, looks for a saved license at ~/.config/threatcrush/<name>/license.json
 * (created by the `*-login` CLI) or `license_key` in module config. If neither
 * is present, the module logs a warning and refuses to start its poll loop.
 *
 * Replace `fetchPaidFeed()` and the auth stub in ./auth.ts with calls to your
 * actual upstream API.
 */

import type {
  ThreatCrushModule,
  ModuleContext,
  ThreatEvent,
} from '@threatcrush/sdk';
import { readLicense, validateWithBackend, MODULE_NAME } from './auth.js';

interface PaidFeedItem {
  id: string;
  observed_at: string;
  indicator: string;
  threat: string;
}

export default class PaidFeedExampleModule implements ThreatCrushModule {
  name = MODULE_NAME;
  version = '0.1.0';
  description = 'Paid module template — auth-gated upstream feed ingest';

  private ctx!: ModuleContext;
  private timer: NodeJS.Timeout | null = null;
  private licenseKey: string | null = null;

  async init(ctx: ModuleContext): Promise<void> {
    this.ctx = ctx;

    const fromConfig = (this.ctx.config.license_key as string | undefined) ?? null;
    const fromDisk = (await readLicense(this.name))?.license_key ?? null;
    this.licenseKey = fromConfig || fromDisk;

    if (!this.licenseKey) {
      this.ctx.logger.warn(
        '[%s] no license found — run `npx %s-login` to activate. The module will load but will not poll.',
        this.name,
        this.name,
      );
      return;
    }

    const verdict = await validateWithBackend(this.licenseKey);
    if (!verdict.ok) {
      this.ctx.logger.error(
        '[%s] license rejected: %s. Re-run `npx %s-login`.',
        this.name,
        verdict.reason,
        this.name,
      );
      this.licenseKey = null;
      return;
    }

    this.ctx.logger.info('[%s] license OK, ready', this.name);
  }

  async start(): Promise<void> {
    if (!this.licenseKey) {
      this.ctx.logger.warn(
        '[%s] start() called without a valid license — skipping poll loop',
        this.name,
      );
      return;
    }
    const intervalSec =
      (this.ctx.config.poll_interval_seconds as number | undefined) ?? 300;
    this.ctx.logger.info('[%s] polling every %ds', this.name, intervalSec);
    void this.tick();
    this.timer = setInterval(() => void this.tick(), intervalSec * 1000);
  }

  async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.ctx.logger.info('[%s] stopped', this.name);
  }

  private async tick(): Promise<void> {
    if (!this.licenseKey) return;
    const apiBase =
      (this.ctx.config.api_base as string | undefined) ??
      'https://api.example.com';

    let items: PaidFeedItem[] = [];
    try {
      items = await this.fetchPaidFeed(apiBase, this.licenseKey);
    } catch (err) {
      this.ctx.logger.error('[%s] fetch failed: %s', this.name, String(err));
      return;
    }

    const lastSeenId = (this.ctx.getState('last_seen_id') as string) ?? '';
    let newest = lastSeenId;
    let emitted = 0;

    for (const item of items) {
      if (lastSeenId && item.id <= lastSeenId) continue;
      const event: ThreatEvent = {
        timestamp: new Date(item.observed_at),
        module: this.name,
        category: 'network',
        severity: 'medium',
        message: `${item.threat}: ${item.indicator}`,
        details: { upstream_id: item.id, indicator: item.indicator },
      };
      this.ctx.emit(event);
      emitted++;
      if (item.id > newest) newest = item.id;
    }

    if (newest && newest !== lastSeenId) {
      this.ctx.setState('last_seen_id', newest);
    }
    this.ctx.logger.info(
      '[%s] processed %d items, emitted %d',
      this.name,
      items.length,
      emitted,
    );
  }

  private async fetchPaidFeed(
    apiBase: string,
    licenseKey: string,
  ): Promise<PaidFeedItem[]> {
    // TODO: replace with the real upstream call.
    const res = await fetch(`${apiBase}/v1/feed/recent`, {
      headers: {
        Authorization: `Bearer ${licenseKey}`,
        Accept: 'application/json',
      },
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} from ${apiBase}`);
    }
    const data = (await res.json()) as { items?: PaidFeedItem[] };
    return data.items ?? [];
  }
}
