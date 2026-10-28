-- Tenancy tables: service role only.
-- Created: 2026-10-28
--
-- Every read and write of these tables goes through the API, which applies the
-- org / team / fleet rules in one place (apps/web/src/lib/access.ts). No app,
-- CLI, desktop or extension code talks to them through PostgREST with a user
-- JWT. But the old org-wide policies below were still live, and anyone can get
-- a user JWT (sign up) and the anon key (public), so they were a second API
-- that skipped every rule the routes enforce:
--   - any org member, guests included, read every server, detection,
--     hardening finding, remediation, property, alert destination (webhook
--     URLs and secrets) in the org, ignoring team fleets;
--   - an org admin could write organization_members directly (any user, any
--     role, owner included: bypassing the owner-only rule and invite consent),
--     write servers (fleet_id into another org's fleet) and queue remediation
--     actions for any server id with no target checks;
--   - an org's creator could insert anyone into it (org_creator_can_add_self
--     never checked user_id = auth.uid()).
-- On prod (2026-10-28) every one of these reads and writes failed with
-- "infinite recursion detected in policy for relation organization_members"
-- (42P17), because organization_members' own policies select from itself, so
-- the hole was shut by accident: any fix to that recursion would have opened
-- it. Dropping them removes the surface instead of leaving it one edit away.
-- The teams/fleets/agent_keys tables already shipped with no policies
-- (20261001130000); this brings the older tables to the same rule. The
-- service_role policies stay.

DROP POLICY IF EXISTS org_admin_can_manage_servers ON servers;
DROP POLICY IF EXISTS org_member_can_view_servers ON servers;

DROP POLICY IF EXISTS remediation_org_admin_manage ON remediation_actions;
DROP POLICY IF EXISTS remediation_org_member_select ON remediation_actions;

DROP POLICY IF EXISTS allowlists_org_admin_manage ON allowlists;
DROP POLICY IF EXISTS allowlists_org_member_select ON allowlists;

DROP POLICY IF EXISTS org_admin_can_manage_members ON organization_members;
DROP POLICY IF EXISTS org_creator_can_add_self ON organization_members;
DROP POLICY IF EXISTS org_member_can_view_members ON organization_members;

DROP POLICY IF EXISTS org_creator_can_delete ON organizations;
DROP POLICY IF EXISTS org_creator_can_update ON organizations;
DROP POLICY IF EXISTS org_members_can_view ON organizations;

DROP POLICY IF EXISTS detection_org_member_select ON detections;
DROP POLICY IF EXISTS findings_org_member_select ON hardening_findings;

DROP POLICY IF EXISTS properties_admin_manage ON properties;
DROP POLICY IF EXISTS properties_member_select ON properties;
DROP POLICY IF EXISTS property_runs_admin_manage ON property_runs;
DROP POLICY IF EXISTS property_runs_member_select ON property_runs;

DROP POLICY IF EXISTS alert_rules_org_admin_manage ON alert_rules;
DROP POLICY IF EXISTS alert_rules_org_member_select ON alert_rules;
DROP POLICY IF EXISTS alert_dest_org_admin_manage ON alert_destinations;
DROP POLICY IF EXISTS alert_dest_org_member_select ON alert_destinations;
DROP POLICY IF EXISTS alert_deliveries_org_member_select ON alert_deliveries;

DROP POLICY IF EXISTS fleet_inventories_admin_manage ON fleet_inventories;
DROP POLICY IF EXISTS fleet_inventories_member_select ON fleet_inventories;
DROP POLICY IF EXISTS scan_findings_member_select ON scan_findings;
