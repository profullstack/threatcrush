import { AuthProvider } from "@/lib/auth-context";
import ActionCenterContent from "./action-center-content";

export default async function ActionCenterPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return (
    <AuthProvider>
      <ActionCenterContent slug={slug} />
    </AuthProvider>
  );
}
