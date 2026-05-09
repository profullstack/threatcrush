import { AuthProvider } from "@/lib/auth-context";
import AdminContent from "./admin-content";

export const metadata = {
  title: "Admin · ThreatCrush",
  robots: { index: false, follow: false },
};

export default function AdminPage() {
  return (
    <AuthProvider>
      <AdminContent />
    </AuthProvider>
  );
}
