-- Incidents: what `threatcrush investigate --raise`, the daemon (critical
-- detections at ingest) and people raise to humans. One row per open problem,
-- deduped on (org, dedupe_key) while it is not resolved, so a second raise of
-- the same thing updates it instead of paging the team again.
--
-- findings / timeline / recommendations are the investigate report (never
-- secret values: the API refuses anything shaped like key material).
-- Access rules live in apps/web/src/lib/access.ts (incidentRoleOf): a team's
-- incident takes the caller's team role, a team-less one follows the findings
-- rule (owner/admin admin, member write, guest nothing). Every read and write
-- goes through the API with the service role; no anon/authenticated grants.

create table if not exists public.incidents (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  team_id uuid references public.teams(id) on delete set null,
  server_id uuid references public.servers(id) on delete set null,
  title text not null,
  severity text not null check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  source text not null check (source in ('investigate', 'watchdog', 'daemon', 'manual')),
  status text not null default 'open' check (status in ('open', 'acknowledged', 'resolved')),
  dedupe_key text not null,
  summary text not null default '',
  verdict text,
  host text,
  findings jsonb not null default '[]'::jsonb,
  timeline jsonb not null default '[]'::jsonb,
  recommendations jsonb not null default '[]'::jsonb,
  raise_count integer not null default 1,
  assignee_id uuid references auth.users(id) on delete set null,
  created_by_user uuid references auth.users(id) on delete set null,
  created_by_agent_key uuid references public.agent_keys(id) on delete set null,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  acknowledged_at timestamptz,
  resolved_at timestamptz,
  last_notified_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- One live incident per dedupe key; a resolved one frees the key.
create unique index if not exists incidents_open_dedupe
  on public.incidents (org_id, dedupe_key) where status <> 'resolved';
create index if not exists incidents_org_status on public.incidents (org_id, status, last_seen_at desc);
create index if not exists incidents_team on public.incidents (team_id, status);

create table if not exists public.incident_notes (
  id uuid primary key default gen_random_uuid(),
  incident_id uuid not null references public.incidents(id) on delete cascade,
  author_id uuid references auth.users(id) on delete set null,
  body text not null,
  created_at timestamptz not null default now()
);
create index if not exists incident_notes_incident on public.incident_notes (incident_id, created_at);

create table if not exists public.incident_notifications (
  id uuid primary key default gen_random_uuid(),
  incident_id uuid references public.incidents(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  channel text not null check (channel in ('sms', 'email')),
  status text not null check (status in ('sent', 'failed', 'skipped', 'rate_limited')),
  detail text,
  created_at timestamptz not null default now()
);
create index if not exists incident_notifications_incident on public.incident_notifications (incident_id, created_at);
-- The per-person hourly page limit counts these.
create index if not exists incident_notifications_user_recent
  on public.incident_notifications (user_id, channel, created_at desc);

-- Per member, per team: page me for this team's incidents (default yes).
alter table public.team_members add column if not exists notify_incidents boolean not null default true;

alter table public.incidents enable row level security;
alter table public.incident_notes enable row level security;
alter table public.incident_notifications enable row level security;

drop policy if exists incidents_service_role_all on public.incidents;
create policy incidents_service_role_all on public.incidents
  for all to service_role using (true) with check (true);
drop policy if exists incident_notes_service_role_all on public.incident_notes;
create policy incident_notes_service_role_all on public.incident_notes
  for all to service_role using (true) with check (true);
drop policy if exists incident_notifications_service_role_all on public.incident_notifications;
create policy incident_notifications_service_role_all on public.incident_notifications
  for all to service_role using (true) with check (true);

revoke all on public.incidents from anon, authenticated;
revoke all on public.incident_notes from anon, authenticated;
revoke all on public.incident_notifications from anon, authenticated;
