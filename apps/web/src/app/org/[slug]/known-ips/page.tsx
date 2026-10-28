import { AuthProvider } from "@/lib/auth-context";
import KnownIpsContent from "./known-ips-content";

export default async function KnownIpsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return (
    <AuthProvider>
      <KnownIpsContent slug={slug} />
    </AuthProvider>
  );
}
