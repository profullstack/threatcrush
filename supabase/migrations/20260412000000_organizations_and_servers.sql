-- Organizations, members, and servers
-- Created: 2026-04-12

-- ─── Organizations (table only, RLS policies after organization_members exists) ───

CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  created_by UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for fast slug lookups
CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);

-- ─── Organization Members ───

CREATE TABLE IF NOT EXISTS organization_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
  joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(org_id, user_id)
);

-- Indexes for membership lookups
CREATE INDEX IF NOT EXISTS idx_org_members_org ON organization_members(org_id);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);

-- ─── Servers ───

CREATE TABLE IF NOT EXISTS servers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  hostname TEXT,
  ip_address TEXT,
  port INTEGER DEFAULT 22,
  ssh_username TEXT,
  status TEXT NOT NULL DEFAULT 'offline' CHECK (status IN ('online', 'offline', 'unreachable')),
  last_seen TIMESTAMP WITH TIME ZONE,
  threatcrushd_version TEXT,
  created_by UUID NOT NULL REFERENCES user_profiles(id) ON DELETE SET NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for server lookups
CREATE INDEX IF NOT EXISTS idx_servers_org ON servers(org_id);
CREATE INDEX IF NOT EXISTS idx_servers_status ON servers(status);

-- ─── Update user_profiles ───

ALTER TABLE user_profiles
  ADD COLUMN IF NOT EXISTS current_org_id UUID REFERENCES organizations(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_user_profiles_current_org ON user_profiles(current_org_id);

-- ─── Helper: auto-create org membership on org creation ───

CREATE OR REPLACE FUNCTION handle_new_organization()
RETURNS TRIGGER AS $$
BEGIN
  -- Add creator as owner member
  INSERT INTO organization_members (org_id, user_id, role)
  VALUES (NEW.id, NEW.created_by, 'owner')
  ON CONFLICT (org_id, user_id) DO NOTHING;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_organization_created
  AFTER INSERT ON organizations
  FOR EACH ROW
  EXECUTE FUNCTION handle_new_organization();

-- ─── RLS Policies (all tables must exist first) ───

-- organizations RLS
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;

CREATE POLICY org_members_can_view ON organizations
  FOR SELECT
  USING (
    id IN (
      SELECT org_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY org_creator_can_update ON organizations
  FOR UPDATE
  USING (created_by = auth.uid());

CREATE POLICY org_creator_can_delete ON organizations
  FOR DELETE
  USING (created_by = auth.uid());

CREATE POLICY org_service_role_all ON organizations
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- organization_members RLS
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;

CREATE POLICY org_member_can_view_members ON organization_members
  FOR SELECT
  USING (
    org_id IN (
      SELECT org_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY org_admin_can_manage_members ON organization_members
  FOR ALL
  USING (
    org_id IN (
      SELECT org_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  )
  WITH CHECK (
    org_id IN (
      SELECT org_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  );

CREATE POLICY org_creator_can_add_self ON organization_members
  FOR INSERT
  WITH CHECK (
    org_id IN (
      SELECT id FROM organizations WHERE created_by = auth.uid()
    )
  );

CREATE POLICY org_member_service_role_all ON organization_members
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- servers RLS
ALTER TABLE servers ENABLE ROW LEVEL SECURITY;

CREATE POLICY org_member_can_view_servers ON servers
  FOR SELECT
  USING (
    org_id IN (
      SELECT org_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY org_admin_can_manage_servers ON servers
  FOR ALL
  USING (
    org_id IN (
      SELECT org_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  )
  WITH CHECK (
    org_id IN (
      SELECT org_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  );

CREATE POLICY org_server_service_role_all ON servers
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);
