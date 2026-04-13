import "server-only";
import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabaseUrl = SUPABASE_URL || "https://placeholder.supabase.co";
const supabaseAnonKey = SUPABASE_ANON_KEY || "placeholder";
const supabaseServiceKey = SUPABASE_SERVICE_KEY || supabaseAnonKey;

/** Browser/client-side Supabase client (anon key) */
export function getSupabaseClient() {
  return createClient(supabaseUrl, supabaseAnonKey);
}

/** Server-side Supabase client (service role key — full access) */
export function getSupabaseAdmin() {
  const key = supabaseServiceKey || supabaseAnonKey;
  return createClient(supabaseUrl, key);
}

/** Helper to slugify a module name */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}
