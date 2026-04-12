import { AuthProvider } from "@/lib/auth-context";
import NewServerContent from "./new-server-content";

export default function NewServerPage({ params }: { params: { slug: string } }) {
  return (
    <AuthProvider>
      <NewServerContent orgSlug={params.slug} />
    </AuthProvider>
  );
}
