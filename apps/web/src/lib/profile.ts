import "server-only";
import { createProfileStore, type ProfileStore } from "@profullstack/profile";
import { getSupabaseAdmin } from "@/lib/supabase";

// The shared @profullstack/profile fields live on public.user_profiles, keyed
// by the auth user id. Server-only: it runs on the service-role client.
let cached: ProfileStore | null = null;

export function profileStore(): ProfileStore {
  cached ??= createProfileStore(getSupabaseAdmin(), { table: "user_profiles", key: "id" });
  return cached;
}
