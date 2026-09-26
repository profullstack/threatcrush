import type { Metadata } from "next";
import { AuthProvider } from "@/lib/auth-context";
import { usageTopupsEnabled } from "@/lib/usage-topups";
import UsageContent from "./usage-content";

// Read USAGE_TOPUPS_ENABLED per request, not once at build time, so flipping it
// on the server takes effect without a rebuild.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Usage & Billing — ThreatCrush",
  description: "Monitor your AI usage credits, spending, and billing for ThreatCrush modules.",
};

export default function UsagePage() {
  return (
    <AuthProvider>
      <UsageContent topupsEnabled={usageTopupsEnabled()} />
    </AuthProvider>
  );
}
