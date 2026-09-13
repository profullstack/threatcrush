/**
 * Who may manage a GitHub App installation's settings.
 *
 * The app has no link table from users to installations; what it has is the
 * GitHub login that signed in (user_metadata.user_name) and, on each
 * installation, the account it was installed on and the person who installed
 * it. A person manages an installation when either of those is their login.
 * A sign-in by email has no GitHub login and manages nothing, which is the
 * honest answer: there is no way to know which installations are theirs.
 */
export function managesInstallation(
  login: string | null,
  row: { account_login?: string | null; sender_login?: string | null }
): boolean {
  if (!login) return false;
  const mine = login.toLowerCase();
  return (
    (row.account_login ?? "").toLowerCase() === mine ||
    (row.sender_login ?? "").toLowerCase() === mine
  );
}

export type ManagedInstallation = {
  installation_id: number;
  account_login: string | null;
  account_type: string | null;
  repository_selection: string | null;
  status: string;
  announce: boolean;
  installed_at: string | null;
};
