create table if not exists public.psa_integrations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  provider text not null check (provider in ('halopsa')),
  name text not null,
  enabled boolean not null default true,
  config jsonb not null default '{}'::jsonb,
  credential_ciphertext text not null,
  credential_iv text not null,
  credential_tag text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, provider, name)
);

create index if not exists psa_integrations_org_enabled
  on public.psa_integrations (organization_id, enabled);

create table if not exists public.psa_ticket_links (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  integration_id uuid not null references public.psa_integrations(id) on delete cascade,
  incident_id uuid not null references public.incidents(id) on delete cascade,
  external_ticket_id text,
  sync_status text not null default 'syncing'
    check (sync_status in ('syncing', 'synced', 'failed', 'skipped')),
  last_error text,
  last_synced_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (integration_id, incident_id)
);

create index if not exists psa_ticket_links_org_recent
  on public.psa_ticket_links (organization_id, updated_at desc);

alter table public.psa_integrations enable row level security;
alter table public.psa_ticket_links enable row level security;

drop policy if exists psa_integrations_service_role_all on public.psa_integrations;
create policy psa_integrations_service_role_all on public.psa_integrations
  for all to service_role using (true) with check (true);

drop policy if exists psa_ticket_links_service_role_all on public.psa_ticket_links;
create policy psa_ticket_links_service_role_all on public.psa_ticket_links
  for all to service_role using (true) with check (true);

revoke all on public.psa_integrations from anon, authenticated;
revoke all on public.psa_ticket_links from anon, authenticated;
