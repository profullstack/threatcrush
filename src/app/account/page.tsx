"use client";

import { AuthProvider } from "@/lib/auth-context";
import AccountContent from "./account-content";

export default function AccountPage() {
  return (
    <AuthProvider>
      <AccountContent />
    </AuthProvider>
  );
}
