import { createFleetbarHandler } from "@profullstack/fleetbar/server";
import { getFleetbarUser } from "@/lib/fleetbar-session";

/**
 * The server half of the <fleet-bar> panel on /fleet: the same
 * @profullstack/fleetbar handler w3bs.org/fleet mounts, proxying to the
 * signed-in user's "Fleet" project on crawlproof.
 */
const handler = createFleetbarHandler({
  // Read per request through a non-literal key: Next inlines process.env.NAME at build.
  token: () => process.env["CRAWLPROOF_UPTIME_TOKEN"],
  getUser: (request: Request) => getFleetbarUser(request),
});

export const dynamic = "force-dynamic";
export { handler as GET, handler as POST, handler as PUT, handler as PATCH, handler as DELETE };
