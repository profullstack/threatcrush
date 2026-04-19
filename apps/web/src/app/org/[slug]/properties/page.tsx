import { AuthProvider } from "@/lib/auth-context";
import PropertiesContent from "./properties-content";

export default function PropertiesPage({ params }: { params: { slug: string } }) {
  return (
    <AuthProvider>
      <PropertiesContent orgSlug={params.slug} />
    </AuthProvider>
  );
}
