-- Route every critical incident in Profullstack's organization to RiotCoder.
-- The trigger covers repository findings, daemon detections, manual reports,
-- and incidents whose severity is later raised to critical.

ALTER TABLE public.organizations
  ADD COLUMN IF NOT EXISTS critical_incident_assignee_id uuid
    REFERENCES public.user_profiles(id) ON DELETE SET NULL;

-- Seed the organization preference only when RiotCoder is currently a member
-- of the organization or one of its teams. Keep an existing preference intact.
UPDATE public.organizations AS o
SET critical_incident_assignee_id = (
  SELECT p.id
  FROM public.user_profiles AS p
  WHERE lower(p.email) = lower('riotcoder@profullstack.com')
    AND (
      EXISTS (
        SELECT 1 FROM public.organization_members AS om
        WHERE om.org_id = o.id AND om.user_id = p.id
          AND om.role IN ('owner', 'admin', 'member')
      )
      OR EXISTS (
        SELECT 1
        FROM public.team_members AS tm
        JOIN public.teams AS t ON t.id = tm.team_id
        WHERE t.org_id = o.id AND tm.user_id = p.id
      )
    )
  LIMIT 1
)
WHERE o.slug = 'profullstack'
  AND o.critical_incident_assignee_id IS NULL
  AND EXISTS (
    SELECT 1
    FROM public.user_profiles AS p
    WHERE lower(p.email) = lower('riotcoder@profullstack.com')
      AND (
        EXISTS (
          SELECT 1 FROM public.organization_members AS om
          WHERE om.org_id = o.id AND om.user_id = p.id
            AND om.role IN ('owner', 'admin', 'member')
        )
        OR EXISTS (
          SELECT 1
          FROM public.team_members AS tm
          JOIN public.teams AS t ON t.id = tm.team_id
          WHERE t.org_id = o.id AND tm.user_id = p.id
        )
      )
  );

CREATE OR REPLACE FUNCTION public.auto_assign_critical_incident()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  target_user_id uuid;
  prior_sort_order integer;
  had_assignment boolean;
BEGIN
  IF NEW.severity <> 'critical' THEN
    RETURN NEW;
  END IF;

  SELECT o.critical_incident_assignee_id
  INTO target_user_id
  FROM public.organizations AS o
  WHERE o.id = NEW.org_id;

  IF target_user_id IS NULL THEN
    RETURN NEW;
  END IF;

  -- The configured responder can be assigned across all teams in this org.
  -- Assignment grants access to this incident only. Stop routing if they are
  -- no longer an active organization or team member.
  IF NOT EXISTS (
    SELECT 1 FROM public.organization_members AS om
    WHERE om.org_id = NEW.org_id AND om.user_id = target_user_id
      AND om.role IN ('owner', 'admin', 'member')
  ) AND NOT EXISTS (
    SELECT 1
    FROM public.team_members AS tm
    JOIN public.teams AS t ON t.id = tm.team_id
    WHERE t.org_id = NEW.org_id AND tm.user_id = target_user_id
  ) THEN
    RETURN NEW;
  END IF;

  SELECT a.sort_order
  INTO prior_sort_order
  FROM public.incident_fix_assignees AS a
  WHERE a.incident_id = NEW.id AND a.user_id = target_user_id;
  had_assignment := FOUND;

  IF prior_sort_order IS NULL OR prior_sort_order > 0 THEN
    UPDATE public.incident_fix_assignees AS a
    SET sort_order = a.sort_order + 1
    WHERE a.incident_id = NEW.id AND a.user_id <> target_user_id;

    INSERT INTO public.incident_fix_assignees (incident_id, user_id, sort_order)
    VALUES (NEW.id, target_user_id, 0)
    ON CONFLICT (incident_id, user_id)
    DO UPDATE SET sort_order = 0;
  END IF;

  UPDATE public.incidents AS i
  SET assignee_id = target_user_id,
      fix_status = CASE WHEN i.fix_status = 'unassigned' THEN 'assigned' ELSE i.fix_status END,
      fix_updated_at = CASE
        WHEN i.assignee_id IS DISTINCT FROM target_user_id OR i.fix_status = 'unassigned' THEN now()
        ELSE i.fix_updated_at
      END,
      fix_updated_by_user = NULL,
      fix_updated_by_agent_key = NULL
  WHERE i.id = NEW.id
    AND (i.assignee_id IS DISTINCT FROM target_user_id OR i.fix_status = 'unassigned');

  IF NOT had_assignment THEN
    INSERT INTO public.incident_fix_events (incident_id, actor_label, event_type, details)
    VALUES (
      NEW.id,
      'ThreatCrush auto-routing',
      'assignees_changed',
      jsonb_build_object(
        'added', jsonb_build_array(jsonb_build_object('user_id', target_user_id)),
        'removed', '[]'::jsonb,
        'automatic', true,
        'reason', 'critical incident routing'
      )
    );
  END IF;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.auto_assign_critical_incident() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auto_assign_critical_incident() FROM anon, authenticated;

DROP TRIGGER IF EXISTS incidents_auto_assign_critical ON public.incidents;
CREATE TRIGGER incidents_auto_assign_critical
  AFTER INSERT OR UPDATE OF severity ON public.incidents
  FOR EACH ROW
  EXECUTE FUNCTION public.auto_assign_critical_incident();

-- Apply the new routing preference to the existing open critical backlog too.
UPDATE public.incidents
SET severity = 'critical'
WHERE severity = 'critical'
  AND status <> 'resolved'
  AND org_id IN (
    SELECT id FROM public.organizations WHERE slug = 'profullstack'
  );

NOTIFY pgrst, 'reload schema';
