import "server-only";
import { createContactForm, type ContactSubmission } from "@profullstack/contact-form";
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

// contact_requests only has columns for company and topic, so the hire
// form's other extra fields would be lost on the way to the database.
// Append them to the stored message instead of dropping them.
const EXTRA_LABELS: Record<string, string> = {
  target: "App or repo",
  stack: "Stack",
  timeline: "Timeline",
};

export function messageWithExtras(s: Pick<ContactSubmission, "message" | "fields">): string {
  const lines = Object.entries(EXTRA_LABELS)
    .filter(([key]) => s.fields[key])
    .map(([key, label]) => `${label}: ${s.fields[key]}`);
  if (lines.length === 0) return s.message;
  return `${s.message}\n\n---\n${lines.join("\n")}`;
}

/**
 * The one contact form (the /hire inquiry). The page renders it and the
 * route answers it from this object, so the token binding, the honeypot
 * and the questions can never disagree between them.
 */
export const contact = createContactForm({
  binding: "threatcrush:contact",
  brandTerms: ["threatcrush", "threat crush"],
  from: "ThreatCrush <hello@threatcrush.com>",
  to: "hello@threatcrush.com",
  questions: [
    { name: "name", label: "Name", required: true, maxLength: 120, autocomplete: "name" },
    { name: "email", label: "Email", type: "email", required: true, maxLength: 254, autocomplete: "email" },
    { name: "company", label: "Company", autocomplete: "organization" },
    { name: "target", label: "App or repo URL", placeholder: "https://github.com/you/app" },
    { name: "stack", label: "Stack", placeholder: "Node + Postgres on AWS, 3 services" },
    { name: "timeline", label: "Timeline", placeholder: "Customer audit in 3 weeks" },
    {
      name: "message",
      label: "What do you need looked at?",
      type: "textarea",
      required: true,
      rows: 5,
      placeholder:
        "Size of the app, what worries you, whether anyone has assessed it before, compliance driver if there is one…",
    },
    { name: "topic", type: "hidden", value: "hire" },
  ],
  subject: (s) => `[ThreatCrush] New ${s.fields.topic ?? "general"} inquiry from ${s.name}`,
  submitLabel: "Request a scope",
  successMessage:
    "Got it — talk soon. We'll come back with a scope and a fixed price, usually the same business day. If it's urgent, email hello@threatcrush.com.",
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
