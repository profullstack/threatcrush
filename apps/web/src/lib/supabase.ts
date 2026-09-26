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

/**
 * Shared anon client for stateless calls only (getUser(token), resend, ...).
 * Anything that creates a session uses createSupabaseAuthClient() instead.
 */
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

/**
 * A fresh anon client for a single request that signs in, signs up or
 * refreshes a session. NEVER do those on getSupabaseClient(): the singleton
 * keeps the resulting session in memory, and every later request in the
 * process that falls back to "the current session" would act as that user.
 * Discard it when the request ends.
 */
export function createSupabaseAuthClient(): SupabaseClient {
  const url = requireEnv("NEXT_PUBLIC_SUPABASE_URL");
  const anonKey = requireEnv("NEXT_PUBLIC_SUPABASE_ANON_KEY");
  return createClient(url, anonKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
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
