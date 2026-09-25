import { AuthProvider } from "@/lib/auth-context";
import NewServerContent from "./new-server-content";

export default async function NewServerPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return (
    <AuthProvider>
      <NewServerContent orgSlug={slug} />
    </AuthProvider>
  );
}
