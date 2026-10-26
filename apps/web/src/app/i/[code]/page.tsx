import type { Metadata } from "next";
import { AuthProvider } from "@/lib/auth-context";
import { cleanInviteCode, INVITE_BONUS_CREDITS } from "@/lib/credit-codes";
import InviteLanding from "./invite-landing";

export const metadata: Metadata = {
  title: "You're invited — ThreatCrush",
  description: "Someone invited you to ThreatCrush.",
  robots: { index: false, follow: false },
};

export default async function InvitePage({ params }: { params: Promise<{ code: string }> }) {
  const { code: raw } = await params;
  const code = cleanInviteCode(decodeURIComponent(raw));
  return (
    <AuthProvider>
      <main className="pt-24 pb-16 min-h-screen">
        <div className="mx-auto max-w-md px-4 sm:px-6 text-center">
          <p className="font-mono text-sm text-tc-green mb-2 tracking-wider">// INVITE</p>
          <h1 className="text-3xl font-bold text-white">You&apos;re invited</h1>
          <p className="mt-3 text-tc-text-dim">
            Someone on ThreatCrush handed you one of their three invites. Join with it and you both get{" "}
            {INVITE_BONUS_CREDITS} credits (${INVITE_BONUS_CREDITS.toFixed(2)}) once your email is confirmed.
          </p>
          <div className="mt-6 rounded-xl border border-tc-border bg-tc-card p-6 space-y-4">
            <p className="text-sm text-tc-text-dim">
              Invite code: <code className="font-mono text-white">{code}</code>
            </p>
            <InviteLanding code={code} />
          </div>
        </div>
      </main>
    </AuthProvider>
  );
}
