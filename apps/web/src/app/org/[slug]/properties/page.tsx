import { AuthProvider } from "@/lib/auth-context";
import PropertiesContent from "./properties-content";

export default async function PropertiesPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return (
    <AuthProvider>
      <PropertiesContent orgSlug={slug} />
    </AuthProvider>
  );
}
