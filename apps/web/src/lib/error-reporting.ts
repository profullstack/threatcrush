/**
 * Opt-in server-side error reporting for the web app, mirroring the daemon's
 * `apps/cli/src/core/telemetry.ts`: enabled only when `SENTRY_DSN` is set.
 * Without it nothing is imported and nothing leaves the process.
 *
 * `@sentry/node` rather than `@sentry/nextjs`: only server errors are wanted,
 * and Next's `onRequestError` hook already hands them over. `@sentry/nextjs`
 * would add a build plugin, a `next.config` wrapper and a browser bundle for
 * no extra coverage. OpenTelemetry setup, ESM loader hooks and the default
 * integrations are all off, so the SDK patches nothing in the server; it only
 * sends the events captured below.
 */
import type * as SentryNode from "@sentry/node";

/** What Next.js passes to `onRequestError` about the failing request. */
export interface FailedRequest {
  path: string;
  method: string;
}

/** Where in the app the error was thrown, as reported by Next.js. */
export interface FailedRequestContext {
  routerKind: string;
  routePath: string;
  routeType: string;
}

let sentry: typeof SentryNode | null = null;

export async function initErrorReporting(): Promise<void> {
  const dsn = process.env.SENTRY_DSN;
  if (!dsn || sentry) return;

  try {
    // Loaded lazily so a deployment without SENTRY_DSN never loads the SDK.
    const mod = await import("@sentry/node");
    mod.init({
      dsn,
      environment: process.env.NODE_ENV || "production",
      release: process.env.SENTRY_RELEASE,
      serverName: "web",
      sendDefaultPii: false,
      skipOpenTelemetrySetup: true,
      registerEsmLoaderHooks: false,
      defaultIntegrations: false,
      integrations: [
        mod.inboundFiltersIntegration(),
        mod.linkedErrorsIntegration(),
        mod.dedupeIntegration(),
      ],
    });
    sentry = mod;
  } catch (err) {
    console.error("[error-reporting] SENTRY_DSN is set but Sentry failed to start:", err);
  }
}

export function reportRequestError(
  err: unknown,
  request: FailedRequest,
  context: FailedRequestContext,
): void {
  const client = sentry;
  if (!client) return;

  client.withScope((scope) => {
    scope.setTags({
      method: request.method,
      route: context.routePath,
      router_kind: context.routerKind,
      route_type: context.routeType,
    });
    // Headers carry cookies and bearer tokens, and query strings carry
    // password-reset and invite tokens, so only the bare path is sent.
    scope.setContext("request", { method: request.method, path: request.path.split("?")[0] });
    client.captureException(err);
  });
}
