-- The $400 human-reviewed scan, bought at /pricing or /hire through CoinPay
-- (any coin or PayPal). One row per order. The coinpay webhook stamps paid_at
-- on the first settled event and booked_at once the team has been notified.

create table if not exists public.scan_orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  org_id uuid references public.organizations(id) on delete set null,
  email text,
  target text,
  notes text,
  amount_usd numeric(12,2) not null,
  currency text,
  coinpay_payment_id text unique,
  status text not null default 'pending'
    check (status in ('pending','confirmed','forwarded','expired','failed')),
  paid_at timestamptz,
  booked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_scan_orders_user on public.scan_orders (user_id, created_at desc);

-- Service role only: the API reads and writes it on the caller's behalf.
alter table public.scan_orders enable row level security;
revoke all on table public.scan_orders from anon, authenticated;

-- Crawl passes sold over x402 (lib/crawl-gateway.ts onSale). x402 only knows
-- the paying wallet, so payer is an address; property names the site.
create table if not exists public.crawl_sales (
  id uuid primary key default gen_random_uuid(),
  property text not null default 'threatcrush.com',
  payer text,
  ref text,
  user_agent text,
  days int,
  total_cents int,
  currency text,
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.crawl_sales enable row level security;
revoke all on table public.crawl_sales from anon, authenticated;
