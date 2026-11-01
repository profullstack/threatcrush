/** Top-ups are available unless an operator explicitly pauses them. */
export function usageTopupsEnabled(): boolean {
  return !["false", "0", "off"].includes((process.env.USAGE_TOPUPS_ENABLED || "").toLowerCase());
}

export const USAGE_TOPUPS_PAUSED_MESSAGE =
  "AI usage credit top-ups are temporarily disabled. Your existing balance and payment history are unchanged.";
