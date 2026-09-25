import { AuthProvider } from "@/lib/auth-context";
import PropertyDetailContent from "./property-detail-content";

export default async function PropertyDetailPage({ params }: { params: Promise<{ slug: string; id: string }> }) {
  const { slug, id } = await params;
  return (
    <AuthProvider>
      <PropertyDetailContent orgSlug={slug} propertyId={id} />
    </AuthProvider>
  );
}
