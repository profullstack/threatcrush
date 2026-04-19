// Next.js instrumentation entry — loaded once per server boot.
// https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
import type { Instrumentation } from "next";

export async function register(): Promise<void> {
  const { initSentry } = await import("./src/lib/sentry");
  if (process.env.NEXT_RUNTIME === "nodejs") {
    initSentry("server");
  } else if (process.env.NEXT_RUNTIME === "edge") {
    initSentry("edge");
  }
}

export const onRequestError: Instrumentation.onRequestError = async (err, request, context) => {
  const Sentry = await import("@sentry/nextjs");
  Sentry.captureRequestError(err, request, context);
};
