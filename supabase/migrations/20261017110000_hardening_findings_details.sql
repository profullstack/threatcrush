-- Structured data on a hardening finding (issue #312).
--
-- The `os-patches` finding carries its package and CVE list here so the
-- dashboard can count fixes across a fleet without parsing titles. Optional:
-- every other finding, and daemons older than this, send no details and the
-- column stays null.

alter table public.hardening_findings
  add column if not exists details jsonb;

-- Same rules as 20260925100000_cloud_ingest, plus `details`, which is
-- replaced on every report (null when the report has none).
create or replace function public.ingest_hardening_findings(p_rows jsonb)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  affected integer;
begin
  with src as (
    -- Last report for a key within the batch wins.
    select distinct on (r.server_id, r.finding_key) r.*
      from jsonb_to_recordset(p_rows) as r(
        organization_id uuid,
        server_id uuid,
        finding_key text,
        status text,
        severity text,
        title text,
        recommendation text,
        observed_at timestamptz,
        details jsonb,
        ord integer
      )
     order by r.server_id, r.finding_key, r.ord desc
  )
  insert into public.hardening_findings as f (
    organization_id, server_id, finding_key, status, severity, title,
    recommendation, observed_at, details
  )
  select s.organization_id, s.server_id, s.finding_key, s.status, s.severity,
         s.title, s.recommendation, s.observed_at, s.details
    from src s
  on conflict (server_id, finding_key)
  do update set
    status = case
      when excluded.status = 'pass' then 'pass'
      when f.status = 'acknowledged' then 'acknowledged'
      when f.status = 'resolved' and excluded.status = 'warn' then 'resolved'
      else excluded.status
    end,
    resolved_at = case
      when f.status = 'resolved' and excluded.status = 'fail' then null
      else f.resolved_at
    end,
    severity = excluded.severity,
    title = excluded.title,
    recommendation = excluded.recommendation,
    observed_at = excluded.observed_at,
    details = excluded.details;

  get diagnostics affected = row_count;
  return affected;
end;
$$;

revoke execute on function public.ingest_hardening_findings(jsonb) from public, anon, authenticated;
grant execute on function public.ingest_hardening_findings(jsonb) to service_role;
