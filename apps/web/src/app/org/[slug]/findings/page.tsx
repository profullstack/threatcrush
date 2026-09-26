import { AuthProvider } from "@/lib/auth-context";
import FindingsContent from "./findings-content";

export default async function FindingsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return (
    <AuthProvider>
      <FindingsContent slug={slug} />
    </AuthProvider>
  );
}
