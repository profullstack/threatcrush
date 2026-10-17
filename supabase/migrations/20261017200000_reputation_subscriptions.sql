-- Reputation Pro: paid access to the deep reputation lookup
-- (/api/v1/reputation/<ip>): history, the /24 neighbourhood, city, score
-- reasons, a larger daily allowance. Paid in crypto through CoinPay; one row
-- per payment. An org is Pro while any settled row's period has not ended.
-- A renewal stacks on the running period (the webhook computes period_end).

create table if not exists public.reputation_subscriptions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid references auth.users(id) on delete set null,
  plan text not null,
  months int not null check (months between 1 and 36),
  amount_usd numeric(12,2) not null,
  currency text not null,
  coinpay_payment_id text unique,
  status text not null default 'pending'
    check (status in ('pending','confirmed','forwarded','expired','failed')),
  period_start timestamptz,
  period_end timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_reputation_subscriptions_org_period
  on public.reputation_subscriptions (org_id, period_end desc);

-- Service role only: the API reads and writes it on the caller's behalf.
alter table public.reputation_subscriptions enable row level security;
revoke all on table public.reputation_subscriptions from anon, authenticated;

-- The deep lookup reads one address's detections through the existing
-- idx_detections_source_ip; no new index on detections here (building one on
-- a live table belongs in a CONCURRENTLY run by hand, not a migration).
