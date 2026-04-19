import { AuthProvider } from "@/lib/auth-context";
import PropertyDetailContent from "./property-detail-content";

export default function PropertyDetailPage({ params }: { params: { slug: string; id: string } }) {
  return (
    <AuthProvider>
      <PropertyDetailContent orgSlug={params.slug} propertyId={params.id} />
    </AuthProvider>
  );
}
