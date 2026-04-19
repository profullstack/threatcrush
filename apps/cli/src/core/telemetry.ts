/**
 * Opt-in error reporting for the CLI + daemon.
 *
 * Enabled only when `SENTRY_DSN` is set in the environment. Safe to call
 * from both short-lived CLI invocations and the long-running daemon.
 */

let ready = false;
// Keep the import lazy so the CLI doesn't pay the Sentry bundle cost when
// reporting is disabled.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let sentry: any = null;

async function loadSentry(): Promise<void> {
  if (sentry) return;
  try {
    sentry = await import('@sentry/node');
  } catch {
    sentry = null;
  }
}

export async function initTelemetry(context: 'cli' | 'daemon'): Promise<void> {
  if (ready) return;
  const dsn = process.env.SENTRY_DSN;
  if (!dsn) return;

  await loadSentry();
  if (!sentry) return;

  sentry.init({
    dsn,
    environment: process.env.NODE_ENV || 'production',
    release: process.env.SENTRY_RELEASE,
    serverName: context,
    tracesSampleRate: 0,
    beforeSend(event: Record<string, unknown>) {
      const req = (event as { request?: { headers?: Record<string, string> } }).request;
      if (req?.headers) {
        delete req.headers.authorization;
        delete req.headers.cookie;
      }
      return event;
    },
  });

  ready = true;
}

export function captureException(err: unknown): void {
  if (!ready || !sentry) return;
  sentry.captureException(err);
}

export async function flushTelemetry(timeoutMs = 2000): Promise<void> {
  if (!ready || !sentry) return;
  try { await sentry.flush(timeoutMs); } catch { /* ignore */ }
}
