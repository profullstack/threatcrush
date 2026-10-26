"use client";

import AccountContent from "./account-content";
import ProfileFieldsCard from "./profile-fields-card";
import GitHubAppSettings from "./github-app-settings";
import DeleteAccount from "./delete-account";

export default function AccountPage() {
  return (
    <>
      <AccountContent />
      <ProfileFieldsCard />
      <GitHubAppSettings />
      <DeleteAccount />
    </>
  );
}
