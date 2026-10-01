-- Let an invite be org-level, not only team-level, so "add a member" can invite
-- someone who has no account yet instead of dead-ending.
-- Created: 2026-10-01
--
-- team_invites now holds both kinds:
--   team_id set, org_role null   -> team invite (join org as guest + the team)
--   team_id null, org_role set   -> org invite (join the org at that role)

ALTER TABLE team_invites ALTER COLUMN team_id DROP NOT NULL;
ALTER TABLE team_invites ADD COLUMN IF NOT EXISTS org_role TEXT
  CHECK (org_role IN ('owner', 'admin', 'member', 'guest'));

-- Exactly one of the two shapes.
ALTER TABLE team_invites DROP CONSTRAINT IF EXISTS team_invites_shape;
ALTER TABLE team_invites
  ADD CONSTRAINT team_invites_shape CHECK ((team_id IS NOT NULL) <> (org_role IS NOT NULL));

-- One live org invite per address per org (the team one already has its index,
-- which no longer matches org invites because team_id is null there).
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_invites_pending
  ON team_invites(org_id, lower(email))
  WHERE team_id IS NULL AND accepted_at IS NULL AND revoked_at IS NULL;
