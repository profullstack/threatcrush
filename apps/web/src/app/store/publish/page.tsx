import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { cookies } from "next/headers";
import PublishClient from "./publish-client";
import { getSupabaseAdmin } from "@/lib/supabase";

// Auth-gated page — always render at request time.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Publish Module — ThreatCrush",
  description: "Publish a ThreatCrush module to the marketplace.",
};

async function requirePublishAccess() {
  const supabase = getSupabaseAdmin();
  const cookieStore = await cookies();

  const possibleCookies = [
    cookieStore.get("sb-access-token")?.value,
    cookieStore.get("supabase-auth-token")?.value,
  ].filter(Boolean) as string[];

  for (const token of possibleCookies) {
    const { data } = await supabase.auth.getUser(token);
    if (data?.user) {
      return data.user;
    }
  }

  redirect("/auth/login?next=/store/publish");
}

export default async function PublishPage() {
  await requirePublishAccess();
  return <PublishClient />;
}
