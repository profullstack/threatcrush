import { AuthProvider } from "@/lib/auth-context";
import OrgDetailContent from "./org-detail-content";

export default function OrgDetailPage({ params }: { params: { slug: string } }) {
  return (
    <AuthProvider>
      <OrgDetailContent slug={params.slug} />
    </AuthProvider>
  );
}
