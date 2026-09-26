import { AuthProvider } from "@/lib/auth-context";
import OrgSettingsContent from "./org-settings-content";

export default async function OrgSettingsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return (
    <AuthProvider>
      <OrgSettingsContent slug={slug} />
    </AuthProvider>
  );
}
