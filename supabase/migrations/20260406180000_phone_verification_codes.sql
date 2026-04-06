-- Short-lived phone verification codes sent via Telnyx.
-- Codes are stored as sha256 hashes, expire in 10 minutes, and are
-- capped at 5 verification attempts per issue.

create table if not exists public.phone_verification_codes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  phone text not null,
  code_hash text not null,
  attempts integer not null default 0,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists phone_verification_codes_user_id_idx
  on public.phone_verification_codes (user_id, created_at desc);

alter table public.phone_verification_codes enable row level security;

-- No direct client access — all reads/writes happen via the service role
-- from the Next.js API routes.
revoke all on public.phone_verification_codes from anon, authenticated;
