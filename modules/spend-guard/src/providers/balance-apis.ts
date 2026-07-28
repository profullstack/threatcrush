/**
 * Prepaid-balance connectors.
 *
 * A third shape, distinct from the other two already supported:
 *
 *   - Twilio     usage history + cost per unit          → unit-cost anomaly
 *   - ValueSERP  quota + limit + reset date             → pace vs period
 *   - these      a bare prepaid balance, no period      → drawdown rate
 *
 * With no limit and no reset date there is nothing to compute a pace against,
 * so the signal has to come from watching the balance fall between polls. That
 * is strictly better than a low-balance threshold anyway: a threshold fires
 * once the money is gone, whereas drawdown catches the slope while it is
 * steepening.
 *
 * Response shapes captured from live accounts.
 */

import { ProviderError } from './types.js';

export interface BalanceSample {
  label: string;
  balance: number;
  currency: string;
}

export interface BalanceProvider {
  readonly name: string;
  fetchPrepaidBalance(): Promise<BalanceSample>;
}

/**
 * DeepSeek — `GET /user/balance`, `Authorization: Bearer …`
 *
 * Live shape:
 *   { is_available, balance_infos: [ { currency, total_balance,
 *     granted_balance, topped_up_balance } ] }
 */
export class DeepSeekBalance implements BalanceProvider {
  readonly name: string;

  constructor(
    private readonly apiKey: string,
    label = 'deepseek',
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    this.name = label;
  }

  async fetchPrepaidBalance(): Promise<BalanceSample> {
    const res = await this.fetchImpl('https://api.deepseek.com/user/balance', {
      headers: { Authorization: `Bearer ${this.apiKey}` },
    });
    if (!res.ok) {
      throw new ProviderError(`DeepSeek /user/balance returned HTTP ${res.status}`, this.name, res.status);
    }

    const body = (await res.json()) as {
      balance_infos?: Array<{ currency?: string; total_balance?: string }>;
    };
    const info = body.balance_infos?.[0] ?? {};

    return {
      label: this.name,
      balance: Number.parseFloat(info.total_balance ?? '0') || 0,
      currency: info.currency ?? 'USD',
    };
  }
}

/**
 * Moonshot / Kimi — `GET /v1/users/me/balance`
 *
 * Note the host matters: keys are issued per region and are NOT interchangeable
 * between `api.moonshot.ai` and `api.moonshot.cn`. A key for one returns 401 on
 * the other, which reads exactly like a revoked credential — so the host is
 * configurable and defaults to the international endpoint.
 *
 * Live shape:
 *   { code, data: { available_balance, voucher_balance, cash_balance },
 *     status }
 */
export class MoonshotBalance implements BalanceProvider {
  readonly name: string;

  constructor(
    private readonly apiKey: string,
    label = 'moonshot',
    private readonly host = 'https://api.moonshot.ai',
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    this.name = label;
  }

  async fetchPrepaidBalance(): Promise<BalanceSample> {
    const res = await this.fetchImpl(`${this.host}/v1/users/me/balance`, {
      headers: { Authorization: `Bearer ${this.apiKey}` },
    });
    if (!res.ok) {
      const hint =
        res.status === 401
          ? ' (401 — check the host: .ai and .cn keys are not interchangeable)'
          : '';
      throw new ProviderError(
        `Moonshot balance returned HTTP ${res.status}${hint}`,
        this.name,
        res.status,
      );
    }

    const body = (await res.json()) as {
      data?: { available_balance?: number; cash_balance?: number };
    };

    return {
      label: this.name,
      balance: Number(body.data?.available_balance ?? 0),
      currency: 'USD',
    };
  }
}

/**
 * Drawdown between two balance observations, normalised to spend-per-hour.
 *
 * Returns 0 when the balance rose (a top-up) or time did not advance, so a
 * refill can never be misread as negative spend.
 */
export function computeDrawdownPerHour(
  previous: { balance: number; at: number },
  current: { balance: number; at: number },
): number {
  const elapsedHours = (current.at - previous.at) / 3_600_000;
  if (elapsedHours <= 0) return 0;

  const spent = previous.balance - current.balance;
  if (spent <= 0) return 0;

  return spent / elapsedHours;
}
