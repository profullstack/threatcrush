/**
 * Quota connectors for providers that expose credits/usage to an ordinary API
 * key — no admin credential, no billing API.
 *
 * This is what makes coverage practical across a large estate. OpenAI and
 * Anthropic gate their cost APIs behind separately-minted admin keys
 * (`/v1/organization/costs` → 403, `/v1/organizations/usage_report` → 401 for
 * normal project keys), so those need a deliberate setup step. The providers
 * below need nothing beyond the key the app already deploys, which means they
 * can be monitored the moment the module is installed.
 *
 * Response shapes here were captured from live accounts, not from docs.
 */

import type { QuotaSnapshot } from '../quota.js';
import { ProviderError } from './types.js';

export interface QuotaProvider {
  readonly name: string;
  fetchQuota(): Promise<QuotaSnapshot>;
}

const MONTH_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * ValueSERP — `GET /account?api_key=…`
 *
 * Live shape:
 *   account_info: { plan, monthly_credits_limit, monthly_credits_remaining,
 *                   monthly_credits_reset_at }
 */
export class ValueSerpQuota implements QuotaProvider {
  readonly name: string;

  constructor(
    private readonly apiKey: string,
    label = 'valueserp',
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    this.name = label;
  }

  async fetchQuota(): Promise<QuotaSnapshot> {
    const res = await this.fetchImpl(
      `https://api.valueserp.com/account?api_key=${encodeURIComponent(this.apiKey)}`,
    );
    if (!res.ok) {
      throw new ProviderError(`ValueSERP /account returned HTTP ${res.status}`, this.name, res.status);
    }

    const body = (await res.json()) as {
      account_info?: {
        monthly_credits_limit?: number;
        monthly_credits_remaining?: number;
        monthly_credits_reset_at?: string;
      };
    };
    const info = body.account_info ?? {};
    const limit = Number(info.monthly_credits_limit ?? 0);
    const remaining = Number(info.monthly_credits_remaining ?? 0);
    const resetAt = info.monthly_credits_reset_at
      ? Date.parse(info.monthly_credits_reset_at)
      : Date.now() + MONTH_MS;

    return {
      label: this.name,
      used: Math.max(limit - remaining, 0),
      limit,
      resetAt,
      unit: 'credits',
      periodMs: MONTH_MS,
    };
  }
}

/**
 * ElevenLabs — `GET /v1/user/subscription`
 *
 * Live shape:
 *   { tier, character_count, character_limit, status,
 *     next_character_count_reset_unix }
 */
export class ElevenLabsQuota implements QuotaProvider {
  readonly name: string;

  constructor(
    private readonly apiKey: string,
    label = 'elevenlabs',
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    this.name = label;
  }

  async fetchQuota(): Promise<QuotaSnapshot> {
    const res = await this.fetchImpl('https://api.elevenlabs.io/v1/user/subscription', {
      headers: { 'xi-api-key': this.apiKey },
    });
    if (!res.ok) {
      throw new ProviderError(
        `ElevenLabs /v1/user/subscription returned HTTP ${res.status}`,
        this.name,
        res.status,
      );
    }

    const body = (await res.json()) as {
      character_count?: number;
      character_limit?: number;
      next_character_count_reset_unix?: number;
    };

    return {
      label: this.name,
      used: Number(body.character_count ?? 0),
      limit: Number(body.character_limit ?? 0),
      // Provider reports seconds, not milliseconds.
      resetAt: body.next_character_count_reset_unix
        ? body.next_character_count_reset_unix * 1000
        : Date.now() + MONTH_MS,
      unit: 'characters',
      periodMs: MONTH_MS,
    };
  }
}
