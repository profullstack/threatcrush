import "server-only";
import { getSupabaseAdmin } from "@/lib/supabase";
import { sendExpoPush } from "./expo";
import type { PushNotification, PushSendResult } from "./types";
import { sendWebPush, type WebPushTarget } from "./webpush";

interface SubscriptionRow {
  id: string;
  endpoint: string;
  keys: { provider?: string; p256dh?: string; auth?: string } | null;
}

/**
 * Push `notification` to every device registered for the org: Expo tokens
 * from the mobile app and Web Push subscriptions from the PWA. Never throws.
 * Subscriptions the push services report as gone are deleted.
 */
export async function sendOrgPush(
  orgId: string,
  notification: PushNotification,
): Promise<PushSendResult & { devices: number }> {
  const admin = getSupabaseAdmin();
  const { data, error } = await admin
    .from("push_subscriptions")
    .select("id, endpoint, keys")
    .eq("organization_id", orgId);
  if (error) {
    return { devices: 0, sent: 0, dead: [], failures: [`could not load push subscriptions: ${error.message}`] };
  }

  const rows = (data ?? []) as SubscriptionRow[];
  const expoRows = rows.filter((row) => row.keys?.provider === "expo");
  const webRows = rows.filter(
    (row) => row.keys?.provider === "webpush" && row.keys.p256dh && row.keys.auth,
  );

  const [expo, web] = await Promise.all([
    sendExpoPush(expoRows.map((row) => row.endpoint), notification),
    sendWebPush(
      webRows.map((row): WebPushTarget => ({
        endpoint: row.endpoint,
        p256dh: row.keys!.p256dh!,
        auth: row.keys!.auth!,
      })),
      notification,
    ),
  ]);

  const dead = [...expo.dead, ...web.dead];
  if (dead.length > 0) {
    const deadIds = rows.filter((row) => dead.includes(row.endpoint)).map((row) => row.id);
    const { error: deleteError } = await admin.from("push_subscriptions").delete().in("id", deadIds);
    if (deleteError) console.error("[push] failed to delete dead subscriptions:", deleteError.message);
  }

  return {
    devices: expoRows.length + webRows.length,
    sent: expo.sent + web.sent,
    failures: [...expo.failures, ...web.failures],
    dead,
  };
}
