import type { Metadata } from "next";
import { AuthProvider } from "@/lib/auth-context";
import FleetContent from "./fleet-content";

export const metadata: Metadata = {
  title: "Fleet | ThreatCrush",
  description: "SSH and uptime checks for your servers, shared with w3bs.org/fleet.",
  robots: { index: false, follow: false },
};

export default function FleetPage() {
  return (
    <AuthProvider>
      <main className="mx-auto max-w-6xl px-4 pb-16 pt-[calc(var(--tc-header-h)+2rem)] sm:px-6">
        <FleetContent />
      </main>
    </AuthProvider>
  );
}
