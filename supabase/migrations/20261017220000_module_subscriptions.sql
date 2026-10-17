-- Paid first-party modules (Link Watch first): one row per payment or grant.
-- An org may run a paid module while any settled row's period has not ended.
-- Paid in crypto through CoinPay (source 'coinpay', the webhook stamps the
-- period and stacks renewals) or granted by hand (source 'comp', inserted
-- with status 'confirmed' and a period_end, e.g. the house org's full access).

create table if not exists public.module_subscriptions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  module text not null,
  user_id uuid references auth.users(id) on delete set null,
  source text not null default 'coinpay' check (source in ('coinpay','comp')),
  plan text not null,
  months int not null check (months between 1 and 1200),
  amount_usd numeric(12,2) not null default 0,
  currency text,
  coinpay_payment_id text unique,
  status text not null default 'pending'
    check (status in ('pending','confirmed','forwarded','expired','failed')),
  period_start timestamptz,
  period_end timestamptz,
  note text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_module_subscriptions_org_module_period
  on public.module_subscriptions (org_id, module, period_end desc);

-- Service role only: the API reads and writes it on the caller's behalf.
alter table public.module_subscriptions enable row level security;
revoke all on table public.module_subscriptions from anon, authenticated;
