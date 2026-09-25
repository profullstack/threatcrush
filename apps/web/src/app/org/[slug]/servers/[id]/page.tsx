import { AuthProvider } from "@/lib/auth-context";
import ServerDetailContent from "./server-detail-content";

export default async function ServerDetailPage({ params }: { params: Promise<{ slug: string; id: string }> }) {
  const { slug, id } = await params;
  return (
    <AuthProvider>
      <ServerDetailContent orgSlug={slug} serverId={id} />
    </AuthProvider>
  );
}
