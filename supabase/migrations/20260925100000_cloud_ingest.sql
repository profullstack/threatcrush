-- Daemon ↔ cloud pipeline (ingest v2 + cloud-issued remediation).
--
-- 1. Detections are deduplicated on (server_id, rule_id, source_ip, minute of
--    detected_at) so the daemon can resend a batch (spool replay, retry after a
--    5xx) without inflating the feed. A duplicate bumps `occurrences` and
--    `last_detected_at` instead of inserting a row. Rows written before this
--    migration have no dedupe_key and are never merged.
-- 2. Hardening findings are upserted with state rules that respect what a human
--    decided in the dashboard (acknowledged / resolved).
-- 3. Remediations queued in the dashboard are claimed by the daemon with a
--    5-minute lease (`executing`), mirroring claim_next_property_run.
--
-- Additive and idempotent. All functions are service-role only.

-- ─── Detections: dedupe ───

alter table public.detections
  add column if not exists occurrences integer not null default 1,
  add column if not exists last_detected_at timestamptz,
  add column if not exists dedupe_key text;

update public.detections
   set last_detected_at = detected_at
 where last_detected_at is null;

create unique index if not exists idx_detections_dedupe
  on public.detections (server_id, dedupe_key)
  where dedupe_key is not null;

-- p_rows: [{organization_id, server_id, rule_id, severity, title, description,
--           source_ip, username, raw_metadata, detected_at, ord}]
-- Returns one row per distinct dedupe group; `inserted` is false when the group
-- merged into an existing detection.
create or replace function public.ingest_detections(p_rows jsonb)
returns table (
  id uuid,
  organization_id uuid,
  server_id uuid,
  severity text,
  title text,
  description text,
  source_ip text,
  rule_id text,
  detected_at timestamptz,
  occurrences integer,
  inserted boolean
)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
  return query
  with src as (
    select r.*,
           coalesce(r.rule_id, '') || chr(31) || coalesce(r.source_ip, '') || chr(31)
             || to_char(date_trunc('minute', r.detected_at at time zone 'UTC'), 'YYYY-MM-DD"T"HH24:MI"Z"')
             as dedupe_key
      from jsonb_to_recordset(p_rows) as r(
        organization_id uuid,
        server_id uuid,
        rule_id text,
        severity text,
        title text,
        description text,
        source_ip text,
        username text,
        raw_metadata jsonb,
        detected_at timestamptz,
        ord integer
      )
  ),
  grouped as (
    -- A batch can carry the same event twice; ON CONFLICT cannot touch one row
    -- twice in a statement, so collapse in-batch duplicates first. The earliest
    -- event supplies the row's content.
    select distinct on (s.server_id, s.dedupe_key)
           s.organization_id, s.server_id, s.rule_id, s.severity, s.title,
           s.description, s.source_ip, s.username, s.raw_metadata, s.detected_at,
           s.dedupe_key,
           (count(*) over w)::integer as n,
           max(s.detected_at) over w as last_at
      from src s
    window w as (partition by s.server_id, s.dedupe_key)
     order by s.server_id, s.dedupe_key, s.detected_at, s.ord
  )
  insert into public.detections as d (
    organization_id, server_id, rule_id, severity, title, description,
    source_ip, username, raw_metadata, detected_at, last_detected_at,
    occurrences, dedupe_key, status
  )
  select g.organization_id, g.server_id, g.rule_id, g.severity, g.title,
         g.description, g.source_ip, g.username, coalesce(g.raw_metadata, '{}'::jsonb),
         g.detected_at, g.last_at, g.n, g.dedupe_key, 'new'
    from grouped g
  on conflict (server_id, dedupe_key) where dedupe_key is not null
  do update set
    occurrences = d.occurrences + excluded.occurrences,
    last_detected_at = greatest(coalesce(d.last_detected_at, d.detected_at), excluded.last_detected_at)
  returning d.id, d.organization_id, d.server_id, d.severity, d.title,
            d.description, d.source_ip, d.rule_id, d.detected_at, d.occurrences,
            (d.xmax = 0) as inserted;
end;
$$;

revoke execute on function public.ingest_detections(jsonb) from public, anon, authenticated;
grant execute on function public.ingest_detections(jsonb) to service_role;

-- ─── Hardening findings: state-preserving upsert ───

-- p_rows: [{organization_id, server_id, finding_key, status, severity, title,
--           recommendation, observed_at, ord}]  status ∈ pass | warn | fail
-- Rules:
--   * pass always overwrites (the check is fixed);
--   * acknowledged stays acknowledged while the check still warns/fails;
--   * resolved stays resolved on warn; a fail reopens it (resolved_at = null).
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
        ord integer
      )
     order by r.server_id, r.finding_key, r.ord desc
  )
  insert into public.hardening_findings as f (
    organization_id, server_id, finding_key, status, severity, title,
    recommendation, observed_at
  )
  select s.organization_id, s.server_id, s.finding_key, s.status, s.severity,
         s.title, s.recommendation, s.observed_at
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
    observed_at = excluded.observed_at;

  get diagnostics affected = row_count;
  return affected;
end;
$$;

revoke execute on function public.ingest_hardening_findings(jsonb) from public, anon, authenticated;
grant execute on function public.ingest_hardening_findings(jsonb) to service_role;

-- ─── Remediation actions: claim lease ───

alter table public.remediation_actions
  drop constraint if exists remediation_actions_status_check;
alter table public.remediation_actions
  add constraint remediation_actions_status_check
  check (status in ('pending', 'executing', 'executed', 'failed', 'expired', 'reversed'));

create index if not exists idx_remediation_server_queue
  on public.remediation_actions (server_id, created_at)
  where status in ('pending', 'executing');

-- Moves up to p_limit pending actions for one server to `executing` and
-- returns them. Claims older than 5 minutes (the daemon died mid-run) go back
-- to pending first; pending actions whose expiry already passed are marked
-- expired rather than handed to the daemon.
create or replace function public.claim_server_remediations(
  p_org_id uuid,
  p_server_id uuid,
  p_limit integer default 50
)
returns setof public.remediation_actions
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.remediation_actions
     set status = 'pending',
         metadata = coalesce(metadata, '{}'::jsonb) - 'claimed_at'
   where organization_id = p_org_id
     and server_id = p_server_id
     and status = 'executing'
     and (metadata->>'claimed_at')::timestamptz < now() - interval '5 minutes';

  update public.remediation_actions
     set status = 'expired'
   where organization_id = p_org_id
     and server_id = p_server_id
     and status = 'pending'
     and expires_at is not null
     and expires_at <= now();

  return query
  with picked as (
    select ra.id
      from public.remediation_actions ra
     where ra.organization_id = p_org_id
       and ra.server_id = p_server_id
       and ra.status = 'pending'
     order by ra.created_at asc
     for update skip locked
     limit greatest(1, least(coalesce(p_limit, 50), 50))
  )
  update public.remediation_actions ra
     set status = 'executing',
         metadata = coalesce(ra.metadata, '{}'::jsonb)
           || jsonb_build_object('claimed_at', to_jsonb(now()))
    from picked
   where ra.id = picked.id
  returning ra.*;
end;
$$;

revoke execute on function public.claim_server_remediations(uuid, uuid, integer) from public, anon, authenticated;
grant execute on function public.claim_server_remediations(uuid, uuid, integer) to service_role;
