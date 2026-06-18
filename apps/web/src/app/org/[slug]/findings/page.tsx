import { AuthProvider } from "@/lib/auth-context";
import FindingsContent from "./findings-content";

export default function FindingsPage({ params }: { params: { slug: string } }) {
  return (
    <AuthProvider>
      <FindingsContent slug={params.slug} />
    </AuthProvider>
  );
}
