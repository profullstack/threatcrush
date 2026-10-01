import type { Metadata } from "next";
import { AuthProvider } from "@/lib/auth-context";
import InviteClient from "./invite-client";

export const metadata: Metadata = {
  title: "Team Invite — ThreatCrush",
  robots: { index: false, follow: false },
};

export default async function InvitePage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  return (
    <AuthProvider>
      <InviteClient token={token} />
    </AuthProvider>
  );
}
