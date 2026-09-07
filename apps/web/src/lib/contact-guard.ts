import "server-only";
import { createContactGuard } from "@profullstack/stack/email";

/**
 * Shared guard for the public contact form.
 *
 * The page mints a token when it renders; the route verifies one when the
 * form comes back. Both import this instance, because a `binding` or
 * field-name mismatch between them would reject every real submission
 * without saying so.
 *
 * This route had anti-spam switched off entirely (`honeypot: false`) and
 * nothing in its place. The honeypot is back on and now actually rendered,
 * but on its own it would still miss the common case: contact-form spam
 * POSTs straight at /api/contact without loading the page, which leaves a
 * hidden field absent from the body rather than filled. The token is the
 * part a request that skipped the page cannot produce.
 *
 * The secret never reaches the browser, only the signature does. It has to
 * be identical across every instance serving the form, so it falls back to
 * RESEND_API_KEY, which sending already cannot work without.
 */
const secret = process.env.FORM_GUARD_SECRET ?? process.env.RESEND_API_KEY ?? "";

if (!secret) {
  console.warn(
    "contact-guard: no FORM_GUARD_SECRET or RESEND_API_KEY set — the contact form is UNPROTECTED"
  );
}

export const contactGuard = secret
  ? createContactGuard({
      secret,
      binding: "threatcrush:contact",
      brandTerms: ["threatcrush", "threat crush"],
      rateLimit: { max: 5, windowMs: 60 * 60 * 1000 },
      // Set FORM_GUARD_ENFORCE=0 to score without blocking, if a real
      // sender ever reports being turned away.
      requireToken: process.env.FORM_GUARD_ENFORCE !== "0",
    })
  : null;
