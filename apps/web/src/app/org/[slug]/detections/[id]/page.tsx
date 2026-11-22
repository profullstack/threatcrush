import { AuthProvider } from "@/lib/auth-context";
import DetectionDetail from "./detection-detail";

export default async function DetectionDetailPage({ params }: { params: Promise<{ slug: string; id: string }> }) {
  const { slug, id } = await params;
  return (
    <AuthProvider>
      <DetectionDetail slug={slug} id={/^[0-9a-f-]{36}$/i.test(id) ? id.toLowerCase() : ""} />
    </AuthProvider>
  );
}
