/**
 * Marketplace review + source-health rules shared by the module API routes,
 * the admin review queue and the store pages. No server-only imports: the
 * store pages use the status helpers too.
 */

export type ReviewStatus = "pending" | "approved" | "rejected";
export type SourceStatus = "ok" | "unreachable" | "not_found";

/** What the admin review queue shows for each listing. */
export const ADMIN_MODULE_COLUMNS =
  "id, slug, display_name, description, author_name, author_email, git_url, homepage_url, npm_package, tarball_url, pricing_type, price_usd, downloads, published, review_status, reviewed_at, review_note, reviewer:reviewed_by(email), source_status, source_checked_at, source_check_detail, created_at, updated_at";

export const PAID_MODULES_UNSUPPORTED =
  "Paid modules aren't supported yet. Submit the module as free (pricing_type \"free\", no price_usd).";

/**
 * There is no purchase or payout flow, so a paid or freemium listing would be
 * a promise the store can't keep. Returns the error to show, or null when the
 * submitted pricing is free.
 */
export function paidModuleError(body: Record<string, unknown>): string | null {
  const { pricing_type: type, price_usd: price } = body;
  if (type != null && type !== "" && type !== "free") return PAID_MODULES_UNSUPPORTED;
  if (price != null && price !== "" && Number(price) !== 0) return PAID_MODULES_UNSUPPORTED;
  return null;
}

export function isPubliclyListed(mod: { published?: boolean | null; review_status?: string | null }): boolean {
  return mod.published === true && mod.review_status === "approved";
}

export function isSourceBroken(status: string | null | undefined): status is "unreachable" | "not_found" {
  return status === "unreachable" || status === "not_found";
}

/** The reason an install is refused because the last source check failed. */
export function brokenSourceMessage(mod: {
  slug: string;
  source_status?: string | null;
  source_checked_at?: string | null;
  source_check_detail?: string | null;
}): string {
  const what = mod.source_status === "not_found" ? "could not be found" : "could not be reached";
  const when = mod.source_checked_at ? ` on ${mod.source_checked_at.slice(0, 10)}` : "";
  const detail = mod.source_check_detail ? ` (${mod.source_check_detail})` : "";
  return `The source for "${mod.slug}" ${what} when it was last checked${when}${detail}. Installs are paused until the listing's source is fixed.`;
}

/** Reviewer identity and notes are for admins and the author, not the public listing. */
export function toPublicModule<T extends Record<string, unknown>>(mod: T): Omit<T, "reviewed_by" | "review_note"> {
  const { reviewed_by: _by, review_note: _note, ...rest } = mod;
  return rest;
}
