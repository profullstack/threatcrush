import { AuthProvider } from "@/lib/auth-context";
import DetectionsContent from "./detections-content";

export default async function DetectionsPage({
  params,
  searchParams,
}: {
  params: Promise<{ slug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { slug } = await params;
  const query = await searchParams;
  const raw = Array.isArray(query.detection) ? query.detection[0] : query.detection;
  // Alert and push links target /org/<slug>/detections?detection=<id>.
  const highlightId = raw && /^[0-9a-f-]{36}$/i.test(raw) ? raw.toLowerCase() : null;

  return (
    <AuthProvider>
      <DetectionsContent slug={slug} highlightId={highlightId} />
    </AuthProvider>
  );
}
