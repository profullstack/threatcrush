/**
 * Opt-in Sentry init. When NEXT_PUBLIC_SENTRY_DSN is unset we skip entirely
 * so local dev and self-hosters don't have to care about error reporting.
 */
import * as Sentry from "@sentry/nextjs";

let initialized = false;

export function initSentry(context: "client" | "server" | "edge"): void {
  if (initialized) return;
  const dsn = process.env.NEXT_PUBLIC_SENTRY_DSN;
  if (!dsn) return;

  Sentry.init({
    dsn,
    environment: process.env.NODE_ENV || "development",
    release: process.env.SENTRY_RELEASE,
    tracesSampleRate: context === "client" ? 0.1 : 0.2,
    profilesSampleRate: 0,
    beforeSend(event) {
      // Strip obvious secrets from stack traces / request bodies.
      if (event.request?.headers) {
        delete event.request.headers.authorization;
        delete event.request.headers.cookie;
      }
      return event;
    },
  });

  initialized = true;
}
