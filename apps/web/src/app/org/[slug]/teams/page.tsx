import { AuthProvider } from "@/lib/auth-context";
import TeamsContent from "./teams-content";

export default async function TeamsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return (
    <AuthProvider>
      <TeamsContent slug={slug} />
    </AuthProvider>
  );
}
