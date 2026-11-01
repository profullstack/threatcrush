/** Top-ups fail closed unless an operator explicitly enables the CoinPay flow. */
export function usageTopupsEnabled(): boolean {
  return process.env.USAGE_TOPUPS_ENABLED === "true";
}

export const USAGE_TOPUPS_PAUSED_MESSAGE =
  "AI usage credit top-ups are temporarily disabled. Your existing balance and payment history are unchanged.";
