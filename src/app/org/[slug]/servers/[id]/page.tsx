import { AuthProvider } from "@/lib/auth-context";
import ServerDetailContent from "./server-detail-content";

export default function ServerDetailPage({ params }: { params: { slug: string; id: string } }) {
  return (
    <AuthProvider>
      <ServerDetailContent orgSlug={params.slug} serverId={params.id} />
    </AuthProvider>
  );
}
