import type { Instrumentation } from "next";

// Error reporting is Node-only: the Sentry SDK used here cannot run on the
// edge runtime, where `middleware.ts` executes. The imports stay dynamic
// because this file is also compiled for the edge runtime, and a static import
// would pull the Node SDK into that bundle.
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { initErrorReporting } = await import("./lib/error-reporting");
  await initErrorReporting();
}

export const onRequestError: Instrumentation.onRequestError = async (err, request, context) => {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { reportRequestError } = await import("./lib/error-reporting");
  reportRequestError(err, request, context);
};
