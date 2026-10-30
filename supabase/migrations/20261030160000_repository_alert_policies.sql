-- CI connections are scoped to one repository and organization. Only a SHA-256
-- digest is stored; a connection cannot read or change account settings.
create table public.github_repository_policies (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  team_id uuid references public.teams(id) on delete set null,
  full_name text not null,
  token_hash text not null unique,
  silence_warnings boolean not null default false,
  silence_examples boolean not null default false,
  last_report_at timestamptz,
  last_counts jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(org_id, full_name)
);
alter table public.github_repository_policies enable row level security;
-- Service-role routes authenticate users and check organization admin access.
-- No client policies: CI token digests must never be exposed to clients.
