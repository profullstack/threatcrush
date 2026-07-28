/**
 * Alchemy connector.
 *
 * Alchemy publishes **no billing or usage API** — compute-unit consumption is
 * visible only in the dashboard. Probing `dashboard.alchemy.com/api/usage` and
 * `api.g.alchemy.com/v1/usage` with a valid key returns 404/429, not data. So
 * unlike the Twilio connector, this one cannot poll spend, and pretending
 * otherwise would ship a detector that silently never fires.
 *
 * What Alchemy *does* expose, for free, is the one state that actually matters:
 * when the monthly capacity limit is reached, every JSON-RPC call starts
 * returning a distinctive 429. That is the moment your app breaks — and it is
 * detectable with a single cheap `eth_blockNumber`.
 *
 * This connector therefore monitors **quota state, not spend**:
 *
 *   healthy    → RPC answers normally
 *   exhausted  → monthly capacity limit hit; every dependent app is now failing
 *   forbidden  → key rejected (revoked, rotated, or wrong app)
 *
 * `exhausted` is critical rather than a warning. It is simultaneously a billing
 * event and an outage: the drain has already happened, and everything relying
 * on this key is down until someone raises the cap or the month rolls over.
 *
 * Derived from a real case where a shared key silently hit its cap and took the
 * dependent service's on-chain quoting offline with no alert of any kind.
 */

import type { UsageSample } from '../detectors.js';
import { ProviderError, type BalanceSnapshot, type SpendProvider } from './types.js';

export type QuotaState = 'healthy' | 'exhausted' | 'forbidden' | 'unknown';

export interface QuotaProbe {
  state: QuotaState;
  /** Provider-supplied explanation, surfaced verbatim in the alert. */
  detail?: string;
}

/** Alchemy's capacity-limit response is a 429 inside a JSON-RPC error body. */
export function classifyRpcResponse(status: number, body: unknown): QuotaProbe {
  const message =
    typeof body === 'object' && body !== null && 'error' in body
      ? String((body as { error?: { message?: string } }).error?.message ?? '')
      : '';

  if (/capacity limit|monthly capacity/i.test(message)) {
    return { state: 'exhausted', detail: message };
  }
  if (status === 429) {
    return { state: 'exhausted', detail: message || 'HTTP 429 from Alchemy' };
  }
  if (status === 401 || status === 403) {
    return { state: 'forbidden', detail: message || `HTTP ${status} — key rejected` };
  }
  if (status >= 200 && status < 300) {
    return { state: 'healthy' };
  }
  return { state: 'unknown', detail: message || `HTTP ${status}` };
}

export interface AlchemyConfig {
  /** Full RPC URL including the key, e.g. https://base-mainnet.g.alchemy.com/v2/KEY */
  rpcUrl: string;
  /** Label for events — the app this key belongs to. */
  label?: string;
}

export class AlchemyProvider implements SpendProvider {
  readonly name: string;

  constructor(
    private readonly config: AlchemyConfig,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    this.name = config.label ? `alchemy:${config.label}` : 'alchemy';
  }

  /**
   * Alchemy has no usage API. Returning an empty series is deliberate and
   * honest: the volume/unit-cost detectors simply have nothing to score, and
   * quota state is reported through `probeQuota` instead.
   */
  async fetchUsage(): Promise<UsageSample[]> {
    return [];
  }

  /** Alchemy is subscription-billed, not prepaid — there is no balance. */
  async fetchBalance(): Promise<BalanceSnapshot | null> {
    return null;
  }

  /**
   * Cheapest possible call that still exercises the quota. `eth_blockNumber`
   * costs a handful of compute units, so polling it every 15 minutes is
   * negligible against any plan.
   */
  async probeQuota(): Promise<QuotaProbe> {
    let res: Response;
    try {
      res = await this.fetchImpl(this.config.rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: [] }),
      });
    } catch (err) {
      throw new ProviderError(`Alchemy probe failed: ${String(err)}`, this.name);
    }

    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      // Non-JSON body still classifies on status alone.
    }

    return classifyRpcResponse(res.status, body);
  }
}

/** Redact the key from an Alchemy URL before it reaches a log or alert. */
export function redactRpcUrl(url: string): string {
  return url.replace(/\/(v2|v1)\/[^/?#]+/, '/$1/<KEY>');
}
