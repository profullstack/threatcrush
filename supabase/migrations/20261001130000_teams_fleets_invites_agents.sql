-- Organizations -> teams -> fleets -> servers, with invites and agent keys.
-- Created: 2026-10-01
--
-- A team owns fleets (named groups of servers) and has members, each with a
-- role on everything the team owns:
--   read   see fleets, servers, detections, findings, reports
--   write  also act on them (daemons reporting in, resolving findings, bans)
--   admin  also manage the team: its fleets, members, invites and agent keys
-- Org owners and admins can do everything in every team. A server in no fleet
-- keeps today's behaviour: every org member can see and act on it.
--
-- Invites and agent keys follow @profullstack/orgs' invite model: 32 random
-- bytes, base64url, only the SHA-256 stored, plaintext shown once.

-- Someone who joins through a team invite becomes an org "guest": they see
-- their teams' fleets and nothing else. ("member" sees every server that is in
-- no fleet, so a read-only invitee must not get it.)
ALTER TABLE organization_members DROP CONSTRAINT IF EXISTS organization_members_role_check;
ALTER TABLE organization_members
  ADD CONSTRAINT organization_members_role_check CHECK (role IN ('owner', 'admin', 'member', 'guest'));

CREATE TABLE IF NOT EXISTS teams (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 100),
  slug TEXT NOT NULL CHECK (slug ~ '^[a-z0-9-]{1,64}$'),
  created_by UUID REFERENCES user_profiles(id) ON DELETE SET NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, slug)
);
CREATE INDEX IF NOT EXISTS idx_teams_org ON teams(org_id);

CREATE TABLE IF NOT EXISTS team_members (
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'read' CHECK (role IN ('read', 'write', 'admin')),
  added_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  PRIMARY KEY (team_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);

CREATE TABLE IF NOT EXISTS fleets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 100),
  slug TEXT NOT NULL CHECK (slug ~ '^[a-z0-9-]{1,64}$'),
  created_by UUID REFERENCES user_profiles(id) ON DELETE SET NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, slug)
);
CREATE INDEX IF NOT EXISTS idx_fleets_team ON fleets(team_id);

-- Deleting a fleet returns its servers to the org (no fleet), never deletes them.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS fleet_id UUID REFERENCES fleets(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_servers_fleet ON servers(fleet_id);

CREATE TABLE IF NOT EXISTS team_invites (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  email TEXT NOT NULL CHECK (position('@' in email) > 1),
  role TEXT NOT NULL DEFAULT 'read' CHECK (role IN ('read', 'write', 'admin')),
  token_hash TEXT NOT NULL UNIQUE,
  invited_by UUID REFERENCES user_profiles(id) ON DELETE SET NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW() + INTERVAL '14 days',
  accepted_at TIMESTAMP WITH TIME ZONE,
  accepted_by UUID REFERENCES user_profiles(id) ON DELETE SET NULL,
  revoked_at TIMESTAMP WITH TIME ZONE
);
-- One live invite per address per team; re-inviting revokes the old one first.
CREATE UNIQUE INDEX IF NOT EXISTS idx_team_invites_pending
  ON team_invites(team_id, lower(email)) WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- An agent (an AI, a script, CI) is a key, not a user: it acts on one team's
-- fleets with one role and nothing else.
CREATE TABLE IF NOT EXISTS agent_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 100),
  role TEXT NOT NULL DEFAULT 'read' CHECK (role IN ('read', 'write', 'admin')),
  -- First characters of the key, shown in the UI so a key can be recognised.
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  created_by UUID REFERENCES user_profiles(id) ON DELETE SET NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMP WITH TIME ZONE,
  revoked_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_agent_keys_team ON agent_keys(team_id);

-- Service role only: every read and write goes through the API, which applies
-- the role rules above in one place (lib/access.ts).
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE fleets ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_keys ENABLE ROW LEVEL SECURITY;
