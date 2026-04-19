-- Property runs: history + queue for scan/pentest executions.
-- Created: 2026-04-19

-- Add scheduling to properties
ALTER TABLE properties
  ADD COLUMN IF NOT EXISTS schedule TEXT
    CHECK (schedule IS NULL OR schedule IN ('hourly', 'daily', 'weekly', 'monthly')),
  ADD COLUMN IF NOT EXISTS next_run_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX IF NOT EXISTS idx_properties_next_run_at ON properties(next_run_at);

-- Runs table
CREATE TABLE IF NOT EXISTS property_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  property_id UUID NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('scan', 'pentest')),
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  trigger TEXT NOT NULL DEFAULT 'manual'
    CHECK (trigger IN ('manual', 'schedule', 'api', 'cli')),
  source TEXT,                    -- 'local' | 'server' | 'daemon' | hostname tag
  worker_id TEXT,                 -- who claimed the run
  queued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  started_at TIMESTAMP WITH TIME ZONE,
  completed_at TIMESTAMP WITH TIME ZONE,
  findings_count INTEGER NOT NULL DEFAULT 0,
  severity_summary JSONB,         -- { critical:0, high:0, medium:0, low:0, info:0 }
  summary TEXT,                   -- one-line description
  output TEXT,                    -- full text output (truncated)
  findings JSONB,                 -- structured findings
  error TEXT,
  created_by UUID REFERENCES user_profiles(id) ON DELETE SET NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_property_runs_org ON property_runs(org_id);
CREATE INDEX IF NOT EXISTS idx_property_runs_property ON property_runs(property_id);
CREATE INDEX IF NOT EXISTS idx_property_runs_status ON property_runs(status);
CREATE INDEX IF NOT EXISTS idx_property_runs_queued_at ON property_runs(queued_at);

-- RLS
ALTER TABLE property_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY property_runs_member_select ON property_runs
  FOR SELECT
  USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
  );

CREATE POLICY property_runs_admin_manage ON property_runs
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

CREATE POLICY property_runs_service_role_all ON property_runs
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Atomic claim helper for workers (avoids two workers grabbing the same run).
CREATE OR REPLACE FUNCTION claim_next_property_run(p_worker_id TEXT, p_org_ids UUID[])
RETURNS SETOF property_runs
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  claimed UUID;
BEGIN
  SELECT id INTO claimed
    FROM property_runs
    WHERE status = 'queued'
      AND org_id = ANY(p_org_ids)
    ORDER BY queued_at ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1;

  IF claimed IS NULL THEN
    RETURN;
  END IF;

  UPDATE property_runs
    SET status = 'running',
        worker_id = p_worker_id,
        started_at = NOW()
    WHERE id = claimed;

  RETURN QUERY SELECT * FROM property_runs WHERE id = claimed;
END;
$$;
