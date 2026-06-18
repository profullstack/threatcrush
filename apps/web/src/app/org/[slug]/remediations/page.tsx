import { AuthProvider } from "@/lib/auth-context";
import RemediationsContent from "./remediations-content";

export default function RemediationsPage({ params }: { params: { slug: string } }) {
  return (
    <AuthProvider>
      <RemediationsContent slug={params.slug} />
    </AuthProvider>
  );
}
