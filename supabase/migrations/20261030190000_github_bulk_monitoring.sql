-- Account identities prove which GitHub installations this ThreatCrush org
-- can connect. The GitHub user token is used for verification only, not stored.
create table public.github_monitoring_links (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  github_user_id bigint not null,
  github_login text not null,
  allowed_owners jsonb not null default '[]',
  updated_at timestamptz not null default now(),
  unique(org_id, github_user_id)
);
create table public.github_monitoring_oauth_states (
  state_hash text primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  org_id uuid not null references public.organizations(id) on delete cascade,
  verifier text not null,
  expires_at timestamptz not null
);
create table public.github_monitoring_owners (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  installation_id bigint not null references public.github_installations(installation_id) on delete cascade,
  account_id bigint not null,
  account_login text not null,
  enabled boolean not null default true,
  silence_examples boolean not null default true,
  silence_warnings boolean not null default false,
  last_discovery_at timestamptz,
  repository_count integer not null default 0,
  error text,
  unique(org_id,installation_id)
);
create table public.github_monitoring_repositories (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.github_monitoring_owners(id) on delete cascade,
  repo_id bigint not null,
  full_name text not null,
  default_branch text not null,
  pushed_at timestamptz,
  scanned_pushed_at timestamptz,
  status text not null default 'queued' check(status in ('queued','running','complete','failed','removed')),
  lease_until timestamptz,
  next_scan_at timestamptz not null default now(),
  last_scanned_at timestamptz,
  last_counts jsonb,
  truncated boolean not null default false,
  error text,
  unique(owner_id,repo_id)
);
create index on public.github_monitoring_repositories(status,next_scan_at);
alter table public.github_monitoring_links enable row level security;
alter table public.github_monitoring_oauth_states enable row level security;
alter table public.github_monitoring_owners enable row level security;
alter table public.github_monitoring_repositories enable row level security;

-- Durable claims across cron invocations/restarts. Expired leases are retried.
create function public.claim_github_monitoring_job() returns setof public.github_monitoring_repositories
language sql security definer set search_path=public as $$
  update github_monitoring_repositories r set status='running',lease_until=now()+interval '15 minutes'
  where r.id=(select q.id from github_monitoring_repositories q
    join github_monitoring_owners o on o.id=q.owner_id
    join github_installations i on i.installation_id=o.installation_id
    where o.enabled and i.status='active' and q.next_scan_at<=now()
    and (q.status='queued' or (q.status='running' and q.lease_until<now()))
    order by q.next_scan_at,q.id for update of q skip locked limit 1)
  returning r.*;
$$;
revoke all on function public.claim_github_monitoring_job() from public,anon,authenticated;
grant execute on function public.claim_github_monitoring_job() to service_role;

-- Consistent defaults for legacy CI connections too. NULL routes incident pages
-- to organization Owners + Admins using the existing paging service.
alter table public.github_repository_policies alter column silence_examples set default true;
update public.github_repository_policies set silence_examples=true,team_id=null,updated_at=now();
notify pgrst,'reload schema';
