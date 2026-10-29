-- Sign in with CoinPay: one row per CoinPay identity, bound by CoinPay's `sub`.
-- STANDING rule: an account is found by sub only, never by email. `email` is the
-- CoinPay address as unverified contact information; it is never the account's
-- auth email, never marked verified and never unique. One CoinPay identity per
-- account and one account per identity. Service role only (no RLS policies).
create table if not exists public.coinpay_identities (
  sub text primary key,
  user_id uuid not null unique references auth.users(id) on delete cascade,
  email text,
  name text,
  created_at timestamptz not null default now(),
  last_login_at timestamptz
);

alter table public.coinpay_identities enable row level security;
revoke all on public.coinpay_identities from anon, authenticated;
