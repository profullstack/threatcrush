-- Self-serve account deletion (DELETE /api/auth/me) deletes the GoTrue user,
-- which cascades to user_profiles. Two foreign keys onto user_profiles made
-- that either fail or destroy other people's data.
-- Created: 2026-09-25

-- servers.created_by was NOT NULL with ON DELETE SET NULL, so deleting anyone
-- who ever registered a server in an org they share failed with a NOT NULL
-- violation. The server belongs to the org, not to whoever added it: keep it
-- and forget the creator.
ALTER TABLE servers ALTER COLUMN created_by DROP NOT NULL;

-- organizations.created_by was ON DELETE CASCADE: deleting an org's creator
-- silently deleted the org, and with it every other member's servers,
-- detections and alert config, even after ownership had been shared. RESTRICT
-- instead, so any deletion path must first delete the orgs the user alone uses
-- or hand created_by to a remaining member (the account-deletion route does).
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS organizations_created_by_fkey;
ALTER TABLE organizations
  ADD CONSTRAINT organizations_created_by_fkey
  FOREIGN KEY (created_by) REFERENCES user_profiles(id) ON DELETE RESTRICT;
