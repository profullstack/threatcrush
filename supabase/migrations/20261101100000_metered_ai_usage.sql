-- Reserve credits before proxying AI requests, then settle the provider usage
-- and the configured 20% margin in the same transaction.
alter table public.usage_events
  alter column cost_usd type numeric(18,12) using cost_usd::numeric(18,12);

create table if not exists public.usage_reservations (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  amount_usd numeric(18,12) not null check (amount_usd > 0),
  status text not null default 'reserved'
    check (status in ('reserved', 'settled', 'released')),
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  settled_at timestamptz,
  usage_event_id uuid references public.usage_events(id)
);

create index if not exists idx_usage_reservations_user_active
  on public.usage_reservations(user_id, expires_at)
  where status = 'reserved';

alter table public.usage_reservations enable row level security;
revoke all on public.usage_reservations from anon, authenticated;
grant select, insert, update, delete on public.usage_reservations to service_role;

create or replace function public.reserve_ai_usage_credits(
  p_user_id uuid,
  p_amount_usd numeric
) returns uuid
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_credits numeric(18,12);
  v_spent numeric(18,12);
  v_reserved numeric(18,12);
  v_id uuid;
begin
  if p_amount_usd is null or p_amount_usd <= 0 or p_amount_usd > 10 then
    raise exception 'invalid_reservation_amount' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 0));
  delete from public.usage_reservations
    where user_id = p_user_id and status = 'reserved' and expires_at <= now();

  select coalesce(sum(amount_usd), 0) into v_credits
    from public.credit_deposits
    where user_id = p_user_id and status in ('confirmed', 'forwarded');
  select coalesce(sum(cost_usd), 0) into v_spent
    from public.usage_events where user_id = p_user_id;
  select coalesce(sum(amount_usd), 0) into v_reserved
    from public.usage_reservations
    where user_id = p_user_id and status = 'reserved' and expires_at > now();

  if v_credits - v_spent - v_reserved < p_amount_usd then
    raise exception 'insufficient_credits' using errcode = 'P0001';
  end if;

  insert into public.usage_reservations(user_id, amount_usd, expires_at)
    values (p_user_id, p_amount_usd, now() + interval '5 minutes')
    returning id into v_id;
  return v_id;
end;
$$;

create or replace function public.settle_ai_usage_credits(
  p_reservation_id uuid,
  p_user_id uuid,
  p_email text,
  p_provider_cost_usd numeric,
  p_charge_usd numeric,
  p_model text,
  p_prompt_tokens integer,
  p_completion_tokens integer,
  p_cached_tokens integer
) returns uuid
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_reservation public.usage_reservations%rowtype;
  v_event_id uuid;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 0));
  select * into v_reservation
    from public.usage_reservations
    where id = p_reservation_id and user_id = p_user_id
    for update;

  if not found or v_reservation.status <> 'reserved' or v_reservation.expires_at <= now() then
    raise exception 'usage_reservation_not_active' using errcode = 'P0001';
  end if;
  if p_provider_cost_usd is null or p_provider_cost_usd < 0
     or p_charge_usd is null or p_charge_usd < p_provider_cost_usd
     or p_charge_usd > v_reservation.amount_usd then
    raise exception 'usage_charge_outside_reservation' using errcode = '22023';
  end if;

  insert into public.usage_events(
    user_id, email, module, action, cost_usd, request_count, metadata
  ) values (
    p_user_id,
    p_email,
    'openai',
    'responses.create',
    p_charge_usd,
    1,
    jsonb_build_object(
      'provider', 'openai',
      'model', p_model,
      'provider_cost_usd', p_provider_cost_usd,
      'margin_rate', 0.2,
      'prompt_tokens', p_prompt_tokens,
      'completion_tokens', p_completion_tokens,
      'cached_tokens', p_cached_tokens
    )
  ) returning id into v_event_id;

  update public.usage_reservations
    set status = 'settled', settled_at = now(), usage_event_id = v_event_id
    where id = p_reservation_id;
  return v_event_id;
end;
$$;

create or replace function public.release_ai_usage_credits(
  p_reservation_id uuid,
  p_user_id uuid
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_updated integer;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 0));
  update public.usage_reservations
    set status = 'released'
    where id = p_reservation_id and user_id = p_user_id and status = 'reserved';
  get diagnostics v_updated = row_count;
  return v_updated = 1;
end;
$$;

revoke all on function public.reserve_ai_usage_credits(uuid, numeric) from public, anon, authenticated;
revoke all on function public.settle_ai_usage_credits(uuid, uuid, text, numeric, numeric, text, integer, integer, integer) from public, anon, authenticated;
revoke all on function public.release_ai_usage_credits(uuid, uuid) from public, anon, authenticated;
grant execute on function public.reserve_ai_usage_credits(uuid, numeric) to service_role;
grant execute on function public.settle_ai_usage_credits(uuid, uuid, text, numeric, numeric, text, integer, integer, integer) to service_role;
grant execute on function public.release_ai_usage_credits(uuid, uuid) to service_role;
