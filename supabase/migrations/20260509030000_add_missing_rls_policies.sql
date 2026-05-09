-- Add explicit RLS policies on tables that had RLS enabled but no policies.
-- App access is via service-role (bypasses RLS), so this is non-breaking.

-- credit_deposits: financial records, owner-only read
drop policy if exists "Users can read their own credit deposits" on public.credit_deposits;
create policy "Users can read their own credit deposits"
  on public.credit_deposits
  for select
  using (auth.uid() = user_id);

drop policy if exists "Service role full access on credit_deposits" on public.credit_deposits;
create policy "Service role full access on credit_deposits"
  on public.credit_deposits
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- funding_payments: server-side bookkeeping only; public contributor list
-- is exposed via API route, not direct PostgREST.
drop policy if exists "Service role full access on funding_payments" on public.funding_payments;
create policy "Service role full access on funding_payments"
  on public.funding_payments
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- phone_verification_codes: short-lived OTPs — service role only.
drop policy if exists "Service role full access on phone_verification_codes" on public.phone_verification_codes;
create policy "Service role full access on phone_verification_codes"
  on public.phone_verification_codes
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- usage_events: per-user telemetry, owner-only read
drop policy if exists "Users can read their own usage events" on public.usage_events;
create policy "Users can read their own usage events"
  on public.usage_events
  for select
  using (auth.uid() = user_id);

drop policy if exists "Service role full access on usage_events" on public.usage_events;
create policy "Service role full access on usage_events"
  on public.usage_events
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');
