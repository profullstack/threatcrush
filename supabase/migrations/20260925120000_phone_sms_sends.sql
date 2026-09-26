-- Per-number SMS ceiling.
--
-- The only throttle on verification SMS was a 30 s cooldown keyed on the
-- user, and signup skipped even that. Anyone could create accounts in a loop
-- with the same (or a premium-rate) phone number and have us pay Telnyx for
-- every one of them.
--
-- phone_verification_codes cannot count sends: a user's previous code is
-- deleted whenever a new one is issued or verified. This table is an
-- append-only log of SMS sends per normalized number, read by
-- reservePhoneSmsSend() in apps/web/src/lib/phone-verification.ts. Rows only
-- matter for 24 hours and are purged by that same function.
--
-- user_id is informational and deliberately has no foreign key: the Supabase
-- SMS hook sends for users whose row may not be committed yet.

create table if not exists public.phone_sms_sends (
  id uuid primary key default gen_random_uuid(),
  phone text not null,
  user_id uuid,
  created_at timestamptz not null default now()
);

create index if not exists phone_sms_sends_phone_created_at_idx
  on public.phone_sms_sends (phone, created_at);

alter table public.phone_sms_sends enable row level security;

-- Service role only, like phone_verification_codes.
revoke all on public.phone_sms_sends from anon, authenticated;

drop policy if exists "Service role full access on phone_sms_sends" on public.phone_sms_sends;
create policy "Service role full access on phone_sms_sends"
  on public.phone_sms_sends
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');
