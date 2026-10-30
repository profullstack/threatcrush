"use client";

import AccountContent from "./account-content";
import ProfileFieldsCard from "./profile-fields-card";
import GitHubAppSettings from "./github-app-settings";
import DeleteAccount from "./delete-account";
import RepositoryAlertsCard from "./repository-alerts-card";

export default function AccountPage() {
  return (
    <>
      <AccountContent />
      <ProfileFieldsCard />
      <details className="mx-auto max-w-3xl px-6 pb-10 text-tc-text-dim"><summary className="cursor-pointer mb-4">Advanced: scan announcements and individual CI connections</summary><GitHubAppSettings /><RepositoryAlertsCard /></details>
      <DeleteAccount />
    </>
  );
}
