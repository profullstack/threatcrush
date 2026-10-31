-- Structured fix ownership, remediation progress and verification for incidents.
-- ThreatCrush records the work; the assigned people or agents perform it.

ALTER TABLE public.incidents
  ADD COLUMN IF NOT EXISTS fix_status text NOT NULL DEFAULT 'unassigned'
    CHECK (fix_status IN ('unassigned', 'assigned', 'in_progress', 'blocked', 'pr_open', 'testing', 'tested', 'fixed', 'false_positive')),
  ADD COLUMN IF NOT EXISTS fix_pr_url text,
  ADD COLUMN IF NOT EXISTS fix_test_status text NOT NULL DEFAULT 'not_run'
    CHECK (fix_test_status IN ('not_run', 'running', 'passed', 'failed', 'skipped')),
  ADD COLUMN IF NOT EXISTS fix_test_summary text,
  ADD COLUMN IF NOT EXISTS fix_test_url text,
  ADD COLUMN IF NOT EXISTS fix_verification text,
  ADD COLUMN IF NOT EXISTS fix_blocked_reason text,
  ADD COLUMN IF NOT EXISTS fix_updated_at timestamptz,
  ADD COLUMN IF NOT EXISTS fix_updated_by_user uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS fix_updated_by_agent_key uuid REFERENCES public.agent_keys(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS public.incident_fix_assignees (
  incident_id uuid NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  assigned_by_user uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  assigned_by_agent_key uuid REFERENCES public.agent_keys(id) ON DELETE SET NULL,
  assigned_at timestamptz NOT NULL DEFAULT now(),
  sort_order integer NOT NULL DEFAULT 0,
  PRIMARY KEY (incident_id, user_id)
);
CREATE INDEX IF NOT EXISTS incident_fix_assignees_user ON public.incident_fix_assignees(user_id, incident_id);

-- Preserve every existing single assignment when moving to multi-assignment.
INSERT INTO public.incident_fix_assignees (incident_id, user_id)
SELECT id, assignee_id FROM public.incidents WHERE assignee_id IS NOT NULL
ON CONFLICT (incident_id, user_id) DO NOTHING;
UPDATE public.incidents SET fix_status = 'assigned'
WHERE assignee_id IS NOT NULL AND fix_status = 'unassigned';

CREATE TABLE IF NOT EXISTS public.incident_fix_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id uuid NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
  actor_user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  actor_agent_key_id uuid REFERENCES public.agent_keys(id) ON DELETE SET NULL,
  actor_label text NOT NULL,
  event_type text NOT NULL CHECK (event_type IN ('assignees_changed', 'work_updated')),
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS incident_fix_events_incident ON public.incident_fix_events(incident_id, created_at DESC);

ALTER TABLE public.incident_fix_assignees ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_fix_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS incident_fix_assignees_service_role_all ON public.incident_fix_assignees;
CREATE POLICY incident_fix_assignees_service_role_all ON public.incident_fix_assignees
  FOR ALL TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS incident_fix_events_service_role_all ON public.incident_fix_events;
CREATE POLICY incident_fix_events_service_role_all ON public.incident_fix_events
  FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON public.incident_fix_assignees FROM anon, authenticated;
REVOKE ALL ON public.incident_fix_events FROM anon, authenticated;

NOTIFY pgrst, 'reload schema';
