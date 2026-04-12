import { AuthProvider } from "@/lib/auth-context";
import NewServerContent from "./new-server-content";

export default function NewServerPage({ params }: { params: { org_slug: string } }) {
  return (
    <AuthProvider>
      <NewServerContent orgSlug={params.org_slug} />
    </AuthProvider>
  );
}
