import { AuthProvider } from "@/lib/auth-context";
import DetectionsContent from "./detections-content";

export default function DetectionsPage({ params }: { params: { slug: string } }) {
  return (
    <AuthProvider>
      <DetectionsContent slug={params.slug} />
    </AuthProvider>
  );
}
