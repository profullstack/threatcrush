import type { Metadata } from "next";
import { AuthProvider } from "@/lib/auth-context";
import ResolveIncident from "./resolve-incident";

export const metadata: Metadata = {
  title: "Open incident — ThreatCrush",
  robots: { index: false, follow: false },
};

export default async function IncidentShortLinkPage({ params }: { params: Promise<{ code: string }> }) {
  const { code } = await params;
  return (
    <AuthProvider>
      <ResolveIncident code={code} />
    </AuthProvider>
  );
}
