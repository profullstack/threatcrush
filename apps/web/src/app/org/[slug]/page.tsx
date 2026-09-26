import { AuthProvider } from "@/lib/auth-context";
import OrgDetailContent from "./org-detail-content";

export default async function OrgDetailPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return (
    <AuthProvider>
      <OrgDetailContent slug={slug} />
    </AuthProvider>
  );
}
