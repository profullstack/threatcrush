"use client";

import AccountContent from "./account-content";
import GitHubAppSettings from "./github-app-settings";
import DeleteAccount from "./delete-account";

export default function AccountPage() {
  return (
    <>
      <AccountContent />
      <GitHubAppSettings />
      <DeleteAccount />
    </>
  );
}
