/**
 * AI usage-credit top-ups are paused by default. Nothing records AI usage into
 * `usage_events` yet, so a credit bought today could never be spent. Setting
 * `USAGE_TOPUPS_ENABLED=true` turns the top-up route and the /usage buy
 * controls back on; balances and payment history stay visible either way.
 */
export function usageTopupsEnabled(): boolean {
  return process.env.USAGE_TOPUPS_ENABLED === "true";
}

export const USAGE_TOPUPS_PAUSED_MESSAGE =
  "AI usage credit top-ups are paused. Your existing balance and payment history are unchanged.";
