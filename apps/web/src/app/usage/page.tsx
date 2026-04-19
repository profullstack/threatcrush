import type { Metadata } from "next";
import { AuthProvider } from "@/lib/auth-context";
import UsageContent from "./usage-content";

export const metadata: Metadata = {
  title: "Usage & Billing — ThreatCrush",
  description: "Monitor your AI usage credits, spending, and billing for ThreatCrush modules.",
};

export default function UsagePage() {
  return (
    <AuthProvider>
      <UsageContent />
    </AuthProvider>
  );
}
