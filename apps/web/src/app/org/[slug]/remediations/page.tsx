import { AuthProvider } from "@/lib/auth-context";
import RemediationsContent from "./remediations-content";

export default async function RemediationsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return (
    <AuthProvider>
      <RemediationsContent slug={slug} />
    </AuthProvider>
  );
}
