-- Store multiple referral payout wallets per user
create table if not exists public.referral_wallets (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  cryptocurrency text not null,
  wallet_address text not null,
  label text,
  is_primary boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(user_id, cryptocurrency)
);

create index if not exists idx_referral_wallets_user_id on public.referral_wallets(user_id);
create index if not exists idx_referral_wallets_primary on public.referral_wallets(user_id, is_primary);
