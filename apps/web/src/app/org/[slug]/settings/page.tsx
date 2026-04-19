import { AuthProvider } from "@/lib/auth-context";
import OrgSettingsContent from "./org-settings-content";

export default function OrgSettingsPage({ params }: { params: { slug: string } }) {
  return (
    <AuthProvider>
      <OrgSettingsContent slug={params.slug} />
    </AuthProvider>
  );
}
