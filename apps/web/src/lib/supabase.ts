import "server-only";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value || value === "placeholder" || value.includes("placeholder.supabase.co")) {
    throw new Error(
      `[supabase] Missing required env var: ${name}. ` +
        `Set it in .env.local (dev) or your hosting environment (prod).`,
    );
  }
  return value;
}

// Memoized singletons. Creating a Supabase client per call leaks memory: each
// client spins up a GoTrue auth client (with an autoRefreshToken setInterval)
// and a realtime client. With hundreds of calls per request across the app,
// these accumulate until the Node heap OOMs. Reuse one client per role instead.
let adminClient: SupabaseClient | undefined;
let anonClient: SupabaseClient | undefined;

/** Browser/client-side Supabase client (anon key) */
export function getSupabaseClient(): SupabaseClient {
  if (!anonClient) {
    const url = requireEnv("NEXT_PUBLIC_SUPABASE_URL");
    const anonKey = requireEnv("NEXT_PUBLIC_SUPABASE_ANON_KEY");
    anonClient = createClient(url, anonKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
  }
  return anonClient;
}

/** Server-side Supabase client (service role key — full access) */
export function getSupabaseAdmin(): SupabaseClient {
  if (!adminClient) {
    const url = requireEnv("NEXT_PUBLIC_SUPABASE_URL");
    const serviceKey = requireEnv("SUPABASE_SERVICE_ROLE_KEY");
    adminClient = createClient(url, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
  }
  return adminClient;
}

/** Helper to slugify a module name */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}
