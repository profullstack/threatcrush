import { AuthProvider } from "@/lib/auth-context";
import AlertSettingsContent from "./alert-settings-content";

export default async function AlertSettingsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return (
    <AuthProvider>
      <AlertSettingsContent slug={slug} />
    </AuthProvider>
  );
}
