import type { Metadata } from "next";
import { AuthProvider } from "@/lib/auth-context";
import { INVITE_BONUS_CREDITS, INVITE_QUOTA } from "@/lib/credit-codes";
import InvitesContent from "./invites-content";

export const metadata: Metadata = {
  title: "Invites — ThreatCrush",
  description: "Your ThreatCrush invites.",
  robots: { index: false, follow: false },
};

export default function InvitesPage() {
  return (
    <AuthProvider>
      <InvitesContent quota={INVITE_QUOTA} bonus={INVITE_BONUS_CREDITS} />
    </AuthProvider>
  );
}
