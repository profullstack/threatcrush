import { AuthProvider } from "@/lib/auth-context";
import NewPropertyContent from "./new-property-content";

export default async function NewPropertyPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return (
    <AuthProvider>
      <NewPropertyContent orgSlug={slug} />
    </AuthProvider>
  );
}
