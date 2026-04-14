-- Credit balances and usage events for per-user AI usage tracking.
-- Credits are added via top-ups (funding_payments) and consumed by AI module calls.

-- Credit deposits: one row per top-up, linked to the authenticated user
create table if not exists public.credit_deposits (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  email text not null,
  coinpay_payment_id text unique,
  amount_usd numeric(12,2) not null,
  status text not null default 'pending'
    check (status in ('pending','confirmed','forwarded','expired','failed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  confirmed_at timestamptz
);

create index if not exists idx_credit_deposits_user_id on public.credit_deposits(user_id);
create index if not exists idx_credit_deposits_email on public.credit_deposits(email);
create index if not exists idx_credit_deposits_status on public.credit_deposits(status);
create index if not exists idx_credit_deposits_coinpay_payment_id on public.credit_deposits(coinpay_payment_id);

-- Usage events: one row per AI module call
create table if not exists public.usage_events (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  email text not null,
  module text not null,
  action text not null,
  cost_usd numeric(12,6) not null default 0,
  request_count int not null default 1,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_usage_events_user_id on public.usage_events(user_id);
create index if not exists idx_usage_events_email on public.usage_events(email);
create index if not exists idx_usage_events_created_at on public.usage_events(created_at desc);
create index if not exists idx_usage_events_module on public.usage_events(module, created_at desc);

-- RLS: only service role can read/write
alter table public.credit_deposits enable row level security;
alter table public.usage_events enable row level security;

-- No anon policies — only server-side service-role access
