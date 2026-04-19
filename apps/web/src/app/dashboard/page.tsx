import { AuthProvider } from "@/lib/auth-context";
import DashboardContent from "./dashboard-content";

export default function DashboardPage() {
  return (
    <AuthProvider>
      <DashboardContent />
    </AuthProvider>
  );
}
