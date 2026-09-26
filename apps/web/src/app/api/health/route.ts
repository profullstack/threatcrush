import { NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import pkg from "../../../../package.json";

// Every probe must hit the database; a cached 200 would hide an outage.
export const dynamic = "force-dynamic";

// Docker, nginx and uptime monitors poll this. A slow database has to fail the
// probe quickly instead of holding the request open until the prober gives up.
const DB_TIMEOUT_MS = 2000;

async function databaseIsUp(): Promise<boolean> {
  const controller = new AbortController();
  const { promise: timedOut, resolve } = Promise.withResolvers<{ error: unknown }>();
  const timer = setTimeout(() => {
    controller.abort();
    resolve({ error: new Error(`database check timed out after ${DB_TIMEOUT_MS}ms`) });
  }, DB_TIMEOUT_MS);

  try {
    // HEAD request, one row at most: PostgREST runs the query but returns no
    // body, so this proves the API and Postgres both answer.
    const query = getSupabaseAdmin()
      .from("user_profiles")
      .select("id", { head: true })
      .limit(1)
      .abortSignal(controller.signal);
    const { error } = await Promise.race([query, timedOut]);
    if (error) {
      console.error("[health] database check failed:", error);
      return false;
    }
    return true;
  } catch (err) {
    console.error("[health] database check failed:", err);
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export async function GET() {
  const dbUp = await databaseIsUp();
  // The failure detail stays in the server log; the probe only needs up/down.
  return NextResponse.json(
    {
      status: dbUp ? "ok" : "error",
      db: dbUp ? "ok" : "error",
      version: pkg.version,
      uptime: Math.round(process.uptime()),
    },
    { status: dbUp ? 200 : 503, headers: { "Cache-Control": "no-store" } },
  );
}
