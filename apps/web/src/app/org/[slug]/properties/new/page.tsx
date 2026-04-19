import { AuthProvider } from "@/lib/auth-context";
import NewPropertyContent from "./new-property-content";

export default function NewPropertyPage({ params }: { params: { slug: string } }) {
  return (
    <AuthProvider>
      <NewPropertyContent orgSlug={params.slug} />
    </AuthProvider>
  );
}
