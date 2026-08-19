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

// Labels for the extra fields a form may submit (the hire form sends these).
// Used both in the notification email and in the persisted message.
const FIELD_LABELS: Record<string, string> = {
  email: "Valid email",
  target: "App or repo",
  stack: "Stack",
  timeline: "Timeline",
};

// contact_requests only has columns for company and topic, so any other extra
// field would be lost on the way to the database. Append them to the stored
// message instead of dropping them.
function messageWithExtras(s: {
  message: string;
  fields: Record<string, string>;
}): string {
  const extras = Object.entries(s.fields).filter(
    ([key, value]) => key !== "company" && key !== "topic" && value,
  );
  if (extras.length === 0) return s.message;
  const lines = extras.map(([key, value]) => `${FIELD_LABELS[key] ?? key}: ${value}`);
  return `${s.message}\n\n---\n${lines.join("\n")}`;
}

export const POST = createContactRoute({
  from: "ThreatCrush <hello@threatcrush.com>",
  to: "hello@threatcrush.com",
  honeypot: false,
  fieldLabels: FIELD_LABELS,
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
        message: messageWithExtras(s),
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
