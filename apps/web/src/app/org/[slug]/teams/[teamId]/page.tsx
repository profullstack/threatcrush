import { AuthProvider } from "@/lib/auth-context";
import TeamContent from "./team-content";

export default async function TeamPage({ params }: { params: Promise<{ slug: string; teamId: string }> }) {
  const { slug, teamId } = await params;
  return (
    <AuthProvider>
      <TeamContent slug={slug} teamId={teamId} />
    </AuthProvider>
  );
}
