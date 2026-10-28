-- Anonymous usage pings from the CLI (one per ai-scan / ai-scan-run), so the
-- nightly report can count scanner use. ai-scan runs on the user's machine and
-- sends nothing else home. Rows carry counts and environment only: no target,
-- no findings text, no IP. Written by POST /api/telemetry with the service
-- role; RLS on with no policies, so anon/authenticated can neither read nor write.
create table if not exists public.cli_usage_pings (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  event text not null check (event in ('ai-scan', 'ai-scan-run')),
  version text,
  platform text,
  arch text,
  node text,
  ci boolean not null default false,
  install_id uuid,
  probes integer,
  scans integer,
  findings integer not null default 0,
  severity jsonb not null default '{}'::jsonb,
  duration_ms integer,
  failed boolean not null default false
);

create index if not exists cli_usage_pings_created_at on public.cli_usage_pings (created_at desc);

alter table public.cli_usage_pings enable row level security;
revoke all on public.cli_usage_pings from anon, authenticated;
