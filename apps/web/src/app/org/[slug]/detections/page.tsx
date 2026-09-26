import { AuthProvider } from "@/lib/auth-context";
import DetectionsContent from "./detections-content";

export default async function DetectionsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return (
    <AuthProvider>
      <DetectionsContent slug={slug} />
    </AuthProvider>
  );
}
