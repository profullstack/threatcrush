import { AuthProvider } from "@/lib/auth-context";
import AlertSettingsContent from "./alert-settings-content";

export default function AlertSettingsPage({ params }: { params: { slug: string } }) {
  return (
    <AuthProvider>
      <AlertSettingsContent slug={params.slug} />
    </AuthProvider>
  );
}
