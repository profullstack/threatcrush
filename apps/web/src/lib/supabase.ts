import "server-only";
import { createClient } from "@supabase/supabase-js";

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

/** Browser/client-side Supabase client (anon key) */
export function getSupabaseClient() {
  const url = requireEnv("NEXT_PUBLIC_SUPABASE_URL");
  const anonKey = requireEnv("NEXT_PUBLIC_SUPABASE_ANON_KEY");
  return createClient(url, anonKey);
}

/** Server-side Supabase client (service role key — full access) */
export function getSupabaseAdmin() {
  const url = requireEnv("NEXT_PUBLIC_SUPABASE_URL");
  const serviceKey = requireEnv("SUPABASE_SERVICE_ROLE_KEY");
  return createClient(url, serviceKey);
}

/** Helper to slugify a module name */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}
