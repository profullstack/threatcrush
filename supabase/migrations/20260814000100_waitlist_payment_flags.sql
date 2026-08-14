-- TC-18: the anon INSERT policy on waitlist validated only the email shape, so
-- anyone could POST a row with paid = true, payment_method and paid_at set and
-- appear in the paid cohort without paying. Payment state is set by the webhook
-- (service_role), never by the person joining.

drop policy if exists "Anonymous can join waitlist" on public.waitlist;
create policy "Anonymous can join waitlist"
  on public.waitlist
  for insert
  with check (
    char_length(email) between 3 and 254
    and email like '%_@_%.__%'
    and coalesce(paid, false) = false
    and payment_method is null
    and stripe_session_id is null
    and coinpay_invoice_id is null
    and paid_at is null
  );
