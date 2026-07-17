import { createContactRoute } from "@profullstack/stack/email";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

let supabase: SupabaseClient | undefined;
function getSupabase() {
  if (supabase) return supabase;
  // Memoized: a new client per request leaks auth/realtime timers → OOM.
  supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    { auth: { persistSession: false, autoRefreshToken: false } },
  );
  return supabase;
}

export const POST = createContactRoute({
  from: "ThreatCrush <hello@threatcrush.com>",
  to: "hello@threatcrush.com",
  honeypot: false,
  fieldLabels: { email: "Valid email" },
  subject: (s) =>
    `[ThreatCrush] New ${s.fields.topic ?? "general"} inquiry from ${s.name}`,
  onSendError: "ignore",
  persist: async (s) => {
    const { data, error } = await getSupabase()
      .from("contact_requests")
      .insert({
        name: s.name,
        email: s.email.toLowerCase(),
        company: s.fields.company ?? null,
        message: s.message,
        topic: s.fields.topic ?? "general",
      })
      .select("id")
      .single();
    if (error) throw new Error(error.message);
    return data.id as string;
  },
  responses: {
    error: { body: { error: "Failed to submit request" }, status: 500 },
  },
});
