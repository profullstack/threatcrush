-- Tracked scan findings: one row per distinct finding on a property, so people
-- can triage what `threatcrush scan`, `pentest` and `ai-scan` found from the
-- web app (PWA), the desktop app and the CLI. property_runs.findings stays the
-- raw per-run record; this table is the deduped, stateful view of it.
--
-- A finding is keyed by (org, property, source, scope, fingerprint). scope is
-- what the run covered (ai-scan categories, scan path + flags), so a narrower
-- run never marks findings from a wider one as fixed.
--
-- Status: open -> acknowledged / fixed / false_positive / ignored. Sync after
-- each finished run: seen again = last_seen bumped (fixed -> open again);
-- missing from a successful run of the same scope = fixed automatically.
-- false_positive and ignored are never changed by sync.

-- ai-scan runs are stored like scans and pentests.
alter table public.property_runs drop constraint if exists property_runs_type_check;
alter table public.property_runs add constraint property_runs_type_check
  check (type in ('scan', 'pentest', 'ai-scan'));
alter table public.property_runs add column if not exists scope text not null default '';

create table if not exists public.scan_findings (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  property_id uuid not null references public.properties(id) on delete cascade,
  source text not null check (source in ('scan', 'pentest', 'ai-scan')),
  scope text not null default '',
  fingerprint text not null,
  type text not null,
  severity text not null check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  message text not null,
  location text,
  details jsonb not null default '{}'::jsonb,
  status text not null default 'open'
    check (status in ('open', 'acknowledged', 'fixed', 'false_positive', 'ignored')),
  note text,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  first_run_id uuid references public.property_runs(id) on delete set null,
  last_run_id uuid references public.property_runs(id) on delete set null,
  times_seen integer not null default 1,
  resolved_at timestamptz,
  status_changed_at timestamptz,
  status_changed_by uuid references auth.users(id) on delete set null,
  status_source text not null default 'sync' check (status_source in ('sync', 'user', 'agent')),
  unique (org_id, property_id, source, scope, fingerprint)
);

create index if not exists scan_findings_org_status on public.scan_findings (org_id, status, severity);
create index if not exists scan_findings_property on public.scan_findings (property_id, source, scope);
create index if not exists scan_findings_last_seen on public.scan_findings (org_id, last_seen_at desc);

alter table public.scan_findings enable row level security;

drop policy if exists scan_findings_member_select on public.scan_findings;
create policy scan_findings_member_select on public.scan_findings
  for select to authenticated
  using (org_id in (select org_id from public.organization_members
                    where user_id = auth.uid() and role in ('owner', 'admin', 'member')));

drop policy if exists scan_findings_service_role_all on public.scan_findings;
create policy scan_findings_service_role_all on public.scan_findings
  for all to service_role using (true) with check (true);

revoke insert, update, delete on public.scan_findings from anon, authenticated;
revoke select on public.scan_findings from anon;
