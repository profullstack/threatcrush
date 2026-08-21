import { NextRequest, NextResponse } from "next/server";

/**
 * GitHub only ever sends one of these three on the setup redirect: `install`
 * for a fresh install, `update` when permissions or repository access changed,
 * and `request` when a non-admin asked an organisation owner to approve it.
 */
const SETUP_ACTIONS = new Set(["install", "update", "request"]);

/**
 * Installation IDs are numeric. Anything else in that parameter did not come
 * from GitHub, so it is dropped rather than passed on to the page.
 */
const INSTALLATION_ID = /^\d{1,20}$/;

/**
 * GET /api
 *
 * This is the setup URL on the ThreatCrush GitHub App's Marketplace listing.
 * After someone installs the app, GitHub redirects them here with
 * `?code=…&installation_id=…&setup_action=install`, and until this route
 * existed that landed on a 404 — the last thing an installer sees.
 *
 * The `code` is a short-lived user-to-server OAuth code. Nothing here can spend
 * it yet (the app has no client credentials configured), so it is deliberately
 * *not* forwarded to the browser: a code in a page URL leaks through Referer
 * headers and history. Only the installation ID and the action travel on.
 *
 * Requests without those parameters get a small index of the public API, so
 * that /api is a useful document rather than a dead end.
 */
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const appUrl = (process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com").replace(/\/$/, "");

  const rawAction = searchParams.get("setup_action");
  const rawInstallationId = searchParams.get("installation_id");
  const isSetupRedirect = rawAction !== null || rawInstallationId !== null;

  if (isSetupRedirect) {
    const destination = new URL(`${appUrl}/github/installed`);
    const action = rawAction && SETUP_ACTIONS.has(rawAction) ? rawAction : "install";
    destination.searchParams.set("setup_action", action);
    if (rawInstallationId && INSTALLATION_ID.test(rawInstallationId)) {
      destination.searchParams.set("installation_id", rawInstallationId);
    }
    return NextResponse.redirect(destination.toString(), 302);
  }

  return NextResponse.json({
    name: "ThreatCrush API",
    docs: `${appUrl}/docs`,
    endpoints: {
      health: "/api/health",
      scan: "/api/scan",
      modules: "/api/modules",
      githubAppSetup: "/api?setup_action=install&installation_id=…",
    },
  });
}
