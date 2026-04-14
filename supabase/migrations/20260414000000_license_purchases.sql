-- Track license purchase intents for webhook reconciliation
create table if not exists public.license_purchases (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  email text not null,
  coinpay_payment_id text,
  amount_usd numeric(10,2) not null,
  currency text not null,
  status text not null default 'pending', -- pending | confirmed | failed
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_license_purchases_user_id on public.license_purchases(user_id);
create index if not exists idx_license_purchases_coinpay_id on public.license_purchases(coinpay_payment_id);
create index if not exists idx_license_purchases_email on public.license_purchases(email);
