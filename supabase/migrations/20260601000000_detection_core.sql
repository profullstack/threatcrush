-- Detection core data model
-- PRD 00: Detection data model & event ingest
-- Created: 2026-06-01
--
-- Tables: detections, remediation_actions, hardening_findings,
--         allowlists, alert_destinations, alert_rules, rule_registry

-- ─── Detections ───

CREATE TABLE IF NOT EXISTS detections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  rule_id TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  title TEXT NOT NULL,
  description TEXT,
  source_ip TEXT,
  username TEXT,
  raw_metadata JSONB DEFAULT '{}',
  detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'acknowledged', 'resolved')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_detections_org ON detections(organization_id);
CREATE INDEX IF NOT EXISTS idx_detections_server ON detections(server_id);
CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity);
CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status);
CREATE INDEX IF NOT EXISTS idx_detections_detected_at ON detections(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_detections_rule_id ON detections(rule_id);
CREATE INDEX IF NOT EXISTS idx_detections_source_ip ON detections(source_ip);

-- ─── Remediation Actions ───

CREATE TABLE IF NOT EXISTS remediation_actions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  detection_id UUID REFERENCES detections(id) ON DELETE SET NULL,
  action_type TEXT NOT NULL CHECK (action_type IN ('block', 'unblock', 'allowlist_add', 'allowlist_remove')),
  target_value TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'executed', 'failed', 'expired', 'reversed')),
  executed_at TIMESTAMP WITH TIME ZONE,
  expires_at TIMESTAMP WITH TIME ZONE,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_remediation_org ON remediation_actions(organization_id);
CREATE INDEX IF NOT EXISTS idx_remediation_server ON remediation_actions(server_id);
CREATE INDEX IF NOT EXISTS idx_remediation_status ON remediation_actions(status);
CREATE INDEX IF NOT EXISTS idx_remediation_expires ON remediation_actions(expires_at) WHERE expires_at IS NOT NULL;

-- ─── Hardening Findings ───

CREATE TABLE IF NOT EXISTS hardening_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  finding_key TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  status TEXT NOT NULL DEFAULT 'fail' CHECK (status IN ('pass', 'warn', 'fail', 'acknowledged', 'resolved')),
  title TEXT NOT NULL,
  recommendation TEXT,
  observed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(server_id, finding_key)
);

CREATE INDEX IF NOT EXISTS idx_findings_org ON hardening_findings(organization_id);
CREATE INDEX IF NOT EXISTS idx_findings_server ON hardening_findings(server_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON hardening_findings(status);

-- ─── Allowlists ───

CREATE TABLE IF NOT EXISTS allowlists (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('ip', 'cidr', 'user')),
  value TEXT NOT NULL,
  note TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(organization_id, type, value)
);

CREATE INDEX IF NOT EXISTS idx_allowlists_org ON allowlists(organization_id);
CREATE INDEX IF NOT EXISTS idx_allowlists_type ON allowlists(type);

-- ─── Alert Destinations ───

CREATE TABLE IF NOT EXISTS alert_destinations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('slack', 'discord', 'email', 'webhook', 'pagerduty', 'push')),
  config JSONB NOT NULL DEFAULT '{}',
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_dest_org ON alert_destinations(organization_id);

-- ─── Alert Rules ───

CREATE TABLE IF NOT EXISTS alert_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  min_severity TEXT NOT NULL DEFAULT 'medium' CHECK (min_severity IN ('info', 'low', 'medium', 'high', 'critical')),
  server_scope JSONB DEFAULT '[]',
  destination_id UUID NOT NULL REFERENCES alert_destinations(id) ON DELETE CASCADE,
  rate_limit_per_hour INTEGER DEFAULT 60,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_rules_org ON alert_rules(organization_id);
CREATE INDEX IF NOT EXISTS idx_alert_rules_dest ON alert_rules(destination_id);

-- ─── Rule Registry ───

CREATE TABLE IF NOT EXISTS rule_registry (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id TEXT NOT NULL UNIQUE,
  version TEXT NOT NULL DEFAULT '1.0.0',
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  source_path TEXT,
  enabled_by_default BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rule_registry_rule_id ON rule_registry(rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_registry_category ON rule_registry(category);

-- ─── Push Subscriptions (for PWA Web Push) ───

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  endpoint TEXT NOT NULL,
  keys JSONB NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(user_id, endpoint)
);

CREATE INDEX IF NOT EXISTS idx_push_subs_user ON push_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_push_subs_org ON push_subscriptions(organization_id);

-- ─── RLS Policies ───

-- detections RLS
ALTER TABLE detections ENABLE ROW LEVEL SECURITY;

CREATE POLICY detection_org_member_select ON detections
  FOR SELECT USING (
    organization_id IN (
      SELECT org_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY detection_service_role_all ON detections
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- remediation_actions RLS
ALTER TABLE remediation_actions ENABLE ROW LEVEL SECURITY;

CREATE POLICY remediation_org_member_select ON remediation_actions
  FOR SELECT USING (
    organization_id IN (
      SELECT org_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY remediation_org_admin_manage ON remediation_actions
  FOR ALL USING (
    organization_id IN (
      SELECT org_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  ) WITH CHECK (
    organization_id IN (
      SELECT org_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  );

CREATE POLICY remediation_service_role_all ON remediation_actions
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- hardening_findings RLS
ALTER TABLE hardening_findings ENABLE ROW LEVEL SECURITY;

CREATE POLICY findings_org_member_select ON hardening_findings
  FOR SELECT USING (
    organization_id IN (
      SELECT org_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY findings_service_role_all ON hardening_findings
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- allowlists RLS
ALTER TABLE allowlists ENABLE ROW LEVEL SECURITY;

CREATE POLICY allowlists_org_member_select ON allowlists
  FOR SELECT USING (
    organization_id IN (
      SELECT org_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY allowlists_org_admin_manage ON allowlists
  FOR ALL USING (
    organization_id IN (
      SELECT org_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  ) WITH CHECK (
    organization_id IN (
      SELECT org_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  );

CREATE POLICY allowlists_service_role_all ON allowlists
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- alert_destinations RLS
ALTER TABLE alert_destinations ENABLE ROW LEVEL SECURITY;

CREATE POLICY alert_dest_org_member_select ON alert_destinations
  FOR SELECT USING (
    organization_id IN (
      SELECT org_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY alert_dest_org_admin_manage ON alert_destinations
  FOR ALL USING (
    organization_id IN (
      SELECT org_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  ) WITH CHECK (
    organization_id IN (
      SELECT org_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  );

CREATE POLICY alert_dest_service_role_all ON alert_destinations
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- alert_rules RLS
ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY alert_rules_org_member_select ON alert_rules
  FOR SELECT USING (
    organization_id IN (
      SELECT org_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY alert_rules_org_admin_manage ON alert_rules
  FOR ALL USING (
    organization_id IN (
      SELECT org_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  ) WITH CHECK (
    organization_id IN (
      SELECT org_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  );

CREATE POLICY alert_rules_service_role_all ON alert_rules
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- rule_registry RLS
ALTER TABLE rule_registry ENABLE ROW LEVEL SECURITY;

CREATE POLICY rule_registry_public_select ON rule_registry
  FOR SELECT USING (true);

CREATE POLICY rule_registry_service_role_all ON rule_registry
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- push_subscriptions RLS
ALTER TABLE push_subscriptions ENABLE ROW LEVEL SECURITY;

CREATE POLICY push_subs_own_select ON push_subscriptions
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY push_subs_own_manage ON push_subscriptions
  FOR ALL USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

CREATE POLICY push_subs_service_role_all ON push_subscriptions
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);
