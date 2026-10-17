-- Reputation phase 2 (PRD 0020): a daily lookup allowance that survives
-- restarts and is shared by every web process, and watch lists that alert an
-- org when an address or domain it cares about is listed or cleared.

create table if not exists public.reputation_usage (
  caller text not null,
  day date not null,
  n int not null default 0,
  primary key (caller, day)
);

-- One atomic increment per lookup; returns the count after it. Old days are
-- pruned by the same call so the table stays a few rows per caller.
create or replace function public.reputation_take(p_caller text, p_day date, p_n int default 1)
returns int language plpgsql security definer set search_path = public as $$
declare
  v int;
begin
  insert into public.reputation_usage (caller, day, n) values (p_caller, p_day, greatest(p_n, 1))
  on conflict (caller, day) do update set n = public.reputation_usage.n + greatest(p_n, 1)
  returning n into v;
  if random() < 0.01 then
    delete from public.reputation_usage where day < p_day - 7;
  end if;
  return v;
end
$$;

create table if not exists public.reputation_watches (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  indicator text not null,
  kind text not null check (kind in ('ip', 'domain')),
  -- An alert destination to notify; null means every enabled destination of the org.
  destination_id uuid references public.alert_destinations(id) on delete set null,
  note text check (note is null or length(note) <= 200),
  last_listed boolean,
  last_score int,
  last_reasons jsonb not null default '[]'::jsonb,
  last_checked_at timestamptz,
  last_changed_at timestamptz,
  created_at timestamptz not null default now(),
  unique (org_id, indicator)
);

create index if not exists idx_reputation_watches_checked on public.reputation_watches (last_checked_at nulls first);

alter table public.reputation_usage enable row level security;
alter table public.reputation_watches enable row level security;
revoke all on table public.reputation_usage from anon, authenticated;
revoke all on table public.reputation_watches from anon, authenticated;
revoke all on function public.reputation_take(text, date, int) from public, anon, authenticated;
grant execute on function public.reputation_take(text, date, int) to service_role;
