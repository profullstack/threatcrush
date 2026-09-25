/**
 * TC-10: a late `payment.expired` / `payment.failed` (or a lagging status poll)
 * must not flip a settled payment back to unsettled. Once a payment has settled,
 * only another settled state may overwrite it.
 *
 * The guard has to live in the UPDATE's WHERE clause: reading the row first and
 * writing later lets two concurrent deliveries both pass the read, so the later
 * write regresses a row the other request has just settled.
 */
export const SETTLED_PAYMENT_STATUSES = ['confirmed', 'forwarded'] as const;

export function isSettledStatus(status: string): boolean {
  return (SETTLED_PAYMENT_STATUSES as readonly string[]).includes(status);
}

/**
 * PostgREST list literal for `.not('status', 'in', SETTLED_STATUS_LIST)`, which
 * supabase-js sends as `status=not.in.("confirmed","forwarded")`.
 */
export const SETTLED_STATUS_LIST = `(${SETTLED_PAYMENT_STATUSES.map((s) => `"${s}"`).join(',')})`;
