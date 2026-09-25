-- Alert delivery log.
--
-- One row per attempt to deliver a detection to an alert destination by a
-- rule: `sent`, `failed` (with the provider's error), or `rate_limited` when
-- the rule already used its rate_limit_per_hour. Rate limiting counts the
-- rule's sent + failed rows in the trailing hour, hence the (rule_id,
-- created_at) index. Written only by the service role (the ingest route's
-- post-response dispatch); org members may read their org's rows.

CREATE TABLE IF NOT EXISTS alert_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  rule_id UUID REFERENCES alert_rules(id) ON DELETE SET NULL,
  destination_id UUID REFERENCES alert_destinations(id) ON DELETE SET NULL,
  detection_id UUID REFERENCES detections(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('sent', 'failed', 'rate_limited')),
  error TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_deliveries_rule_created
  ON alert_deliveries(rule_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_deliveries_org_created
  ON alert_deliveries(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_deliveries_detection
  ON alert_deliveries(detection_id);

ALTER TABLE alert_deliveries ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS alert_deliveries_org_member_select ON alert_deliveries;
CREATE POLICY alert_deliveries_org_member_select ON alert_deliveries
  FOR SELECT USING (
    organization_id IN (
      SELECT org_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

DROP POLICY IF EXISTS alert_deliveries_service_role_all ON alert_deliveries;
CREATE POLICY alert_deliveries_service_role_all ON alert_deliveries
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);
