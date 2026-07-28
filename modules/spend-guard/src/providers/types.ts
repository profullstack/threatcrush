import type { UsageSample } from '../detectors.js';

export interface BalanceSnapshot {
  balance: number;
  currency: string;
  /**
   * Whether the provider will automatically top the balance up from a stored
   * payment method. Null when the provider does not expose this over its API —
   * which is common, and why the module also lets operators assert it in config.
   */
  autoRechargeEnabled: boolean | null;
}

/**
 * A connector to one metered third-party service.
 *
 * Implementations must be read-only. Containment lives behind a separate,
 * explicitly configured credential so that a compromised agent cannot revoke
 * an estate's worth of provider keys (PRD 0001, open question on credential
 * scope).
 */
export interface SpendProvider {
  /** Stable identifier, used in events and state keys. */
  readonly name: string;

  /** Daily usage broken down by destination where the provider reports it. */
  fetchUsage(sinceIsoDate: string): Promise<UsageSample[]>;

  /** Current balance, or null if the provider has no prepaid concept. */
  fetchBalance(): Promise<BalanceSnapshot | null>;
}

export class ProviderError extends Error {
  constructor(
    message: string,
    readonly provider: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'ProviderError';
  }
}
