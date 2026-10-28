import { AuthProvider } from "@/lib/auth-context";
import IncidentsContent from "./incidents-content";

export default async function IncidentsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return (
    <AuthProvider>
      <IncidentsContent slug={slug} />
    </AuthProvider>
  );
}
