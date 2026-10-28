import { AuthProvider } from "@/lib/auth-context";
import IncidentDetail from "./incident-detail";

export default async function IncidentPage({ params }: { params: Promise<{ slug: string; id: string }> }) {
  const { slug, id } = await params;
  return (
    <AuthProvider>
      <IncidentDetail slug={slug} incidentId={id} />
    </AuthProvider>
  );
}
