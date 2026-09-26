/**
 * Password rules for ThreatCrush accounts, shared by the signup form, the
 * set-new-password form and /api/auth/reset-password so the three cannot drift.
 * GoTrue still applies its own policy on top (e.g. its 72-character ceiling).
 */
export const MIN_PASSWORD_LENGTH = 8;

/** Returns a user-facing reason the password is not acceptable, or null. */
export function passwordPolicyError(password: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  }
  return null;
}
