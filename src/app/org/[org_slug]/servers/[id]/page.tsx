import { AuthProvider } from "@/lib/auth-context";
import ServerDetailContent from "./server-detail-content";

export default function ServerDetailPage({ params }: { params: { org_slug: string; id: string } }) {
  return (
    <AuthProvider>
      <ServerDetailContent orgSlug={params.org_slug} serverId={params.id} />
    </AuthProvider>
  );
}
