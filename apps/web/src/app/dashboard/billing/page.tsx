import type { Metadata } from "next";
import { AuthProvider } from "@/lib/auth-context";
import BillingContent from "./billing-content";

export const metadata: Metadata = {
  title: "Credits & Codes — ThreatCrush",
  description: "Your ThreatCrush credit balance, redeem a credit code, and invite people.",
  robots: { index: false, follow: false },
};

export default function BillingPage() {
  return (
    <AuthProvider>
      <BillingContent />
    </AuthProvider>
  );
}
