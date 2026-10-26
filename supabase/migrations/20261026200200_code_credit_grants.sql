-- Credit codes and invite bonuses land in the ONE credit balance ThreatCrush
-- already has: confirmed rows in credit_deposits minus usage_events (what
-- /usage shows as "Available Balance", balance_usd). One scan credit is $1.00
-- of that balance.
--
-- @profullstack/redeem-credits keeps the codes (sha256 only) and an audit row
-- per redemption in credit_ledger; a grant becomes a credit_deposits row with
-- grant_source set and no coinpay_payment_id. The unique index on
-- (user_id, grant_source) is the idempotency key, so a retried or concurrent
-- write is a no-op and a code or an invite pays each person exactly once.
--
-- grant_source is `code:<codeId>` for a redeemed code and
-- `invite:<inviteId>:<inviter|invitee>` for an invite bonus.

alter table public.credit_deposits add column if not exists grant_source text;

create unique index if not exists credit_deposits_grant_source_uniq
  on public.credit_deposits (user_id, grant_source)
  where grant_source is not null;

-- One accepted invite per account, enforced by the database rather than by a
-- read-then-write in the app (@profullstack/affiliates 0.2 does not check it).
create unique index if not exists aff_invites_one_per_user
  on public.aff_invites (used_by)
  where used_by is not null;

-- Insert the grant row once; return whether it was new and the balance after.
create or replace function public.grant_code_credits(p_user uuid, p_source text, p_credits integer)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_email text;
  v_id uuid;
  v_in numeric;
  v_out numeric;
begin
  if p_credits is null or p_credits < 1 or p_credits > 100000 then
    raise exception 'grant_code_credits: credits out of range (%)', p_credits;
  end if;
  if p_source is null or length(p_source) = 0 or length(p_source) > 200 then
    raise exception 'grant_code_credits: bad source';
  end if;

  select u.email into v_email from auth.users u where u.id = p_user;
  if not found then
    raise exception 'grant_code_credits: no user %', p_user;
  end if;

  insert into public.credit_deposits (user_id, email, amount_usd, status, confirmed_at, grant_source)
  values (p_user, coalesce(v_email, ''), p_credits, 'confirmed', now(), p_source)
  on conflict (user_id, grant_source) where grant_source is not null do nothing
  returning id into v_id;

  select coalesce(sum(d.amount_usd), 0) into v_in
    from public.credit_deposits d
   where d.user_id = p_user and d.status in ('confirmed', 'forwarded');
  select coalesce(sum(e.cost_usd), 0) into v_out
    from public.usage_events e
   where e.user_id = p_user;

  return jsonb_build_object('applied', v_id is not null, 'balance', round(v_in - v_out, 2));
end;
$$;

revoke all on function public.grant_code_credits(uuid, text, integer) from public, anon, authenticated;
grant execute on function public.grant_code_credits(uuid, text, integer) to service_role;
