-- Customer webhooks move onto @profullstack/webhooks 0.2.1.
--
-- The hub keeps endpoints and a durable delivery outbox (retries with backoff
-- for about three days, a delivery log, auto-disable after 20 failures in a
-- row). Its tables are the package's own schemaSql('pg', 'hub_') shape, so a
-- later switch to postgresStore needs no data change. ThreatCrush has no
-- direct Postgres URL in the app, so src/lib/webhooks/supabase-store.ts runs
-- them over supabase-js, with the claim as an RPC (PostgREST cannot lock rows).
--
-- Only the server (service role) touches these tables: RLS on, no policies,
-- the claim RPC granted to service_role alone.
--
-- Idempotent: safe to re-run.

create table if not exists public.hub_webhook_endpoints (
  id text primary key,
  owner text not null,
  url text not null,
  secret text not null,
  events text not null default '["*"]',
  description text not null default '',
  enabled integer not null default 1,
  failures integer not null default 0,
  disabled_reason text,
  created_at bigint not null,
  updated_at bigint not null
);
create index if not exists hub_webhook_endpoints_owner on public.hub_webhook_endpoints(owner);

create table if not exists public.hub_webhook_deliveries (
  id text primary key,
  endpoint_id text not null,
  owner text not null,
  event_id text not null,
  event_type text not null,
  payload text not null,
  status text not null default 'pending',
  attempts integer not null default 0,
  next_at bigint not null,
  last_status integer,
  last_error text,
  created_at bigint not null,
  updated_at bigint not null
);
create index if not exists hub_webhook_deliveries_due on public.hub_webhook_deliveries(status, next_at);
create index if not exists hub_webhook_deliveries_endpoint on public.hub_webhook_deliveries(endpoint_id, created_at);
create index if not exists hub_webhook_deliveries_owner on public.hub_webhook_deliveries(owner, created_at);

alter table public.hub_webhook_endpoints enable row level security;
alter table public.hub_webhook_deliveries enable row level security;
revoke all on public.hub_webhook_endpoints from anon, authenticated;
revoke all on public.hub_webhook_deliveries from anon, authenticated;
grant all on public.hub_webhook_endpoints to service_role;
grant all on public.hub_webhook_deliveries to service_role;

create or replace function public.claim_hub_webhook_deliveries(p_now bigint, p_limit integer, p_lease_until bigint)
returns setof public.hub_webhook_deliveries
language sql
volatile
set search_path to 'public'
as $function$
  update public.hub_webhook_deliveries
     set next_at = p_lease_until
   where id in (
     select id from public.hub_webhook_deliveries
      where status = 'pending' and next_at <= p_now
      order by next_at
      limit p_limit
      for update skip locked
   )
  returning *;
$function$;
revoke execute on function public.claim_hub_webhook_deliveries(bigint, integer, bigint) from public, anon, authenticated;
grant execute on function public.claim_hub_webhook_deliveries(bigint, integer, bigint) to service_role;

-- A rule-routed webhook is queued in the hub and sent later: its
-- alert_deliveries row starts 'queued' (counted against the rule's hourly
-- limit like sent/failed) and the hub moves it to 'sent' or 'failed'.
alter table public.alert_deliveries add column if not exists hub_delivery_id text;
create index if not exists idx_alert_deliveries_hub_delivery
  on public.alert_deliveries(hub_delivery_id) where hub_delivery_id is not null;
alter table public.alert_deliveries drop constraint if exists alert_deliveries_status_check;
alter table public.alert_deliveries add constraint alert_deliveries_status_check
  check (status in ('sent', 'failed', 'rate_limited', 'queued'));

-- Carry every webhook alert destination over to a hub endpoint owned by its
-- org, subscribed to the alert kinds a destination receives, keeping its
-- secret. The old sender keyed HMAC-SHA256 with the UTF-8 bytes of the whole
-- typed secret; the package does the same for any secret except one starting
-- 'whsec_' (it decodes the base64 after the prefix), so only those are
-- re-wrapped as 'whsec_' || base64(the typed string): the same key bytes.
-- A destination with no secret gets a fresh random one (it sent no signature
-- before; X-ThreatCrush-Signature is now always present).
with moved as (
  select
    d.id as dest_id,
    'wh_' || replace(d.id::text, '-', '') as endpoint_id,
    d.organization_id::text as owner,
    btrim(d.config->>'url') as url,
    case
      when coalesce(btrim(d.config->>'secret'), '') = '' then
        'whsec_' || encode(decode(replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''), 'hex'), 'base64')
      when btrim(d.config->>'secret') like 'whsec\_%' then
        'whsec_' || translate(encode(convert_to(btrim(d.config->>'secret'), 'UTF8'), 'base64'), E'\n', '')
      else btrim(d.config->>'secret')
    end as secret,
    left(d.name, 200) as description,
    case when d.enabled then 1 else 0 end as enabled,
    (extract(epoch from d.created_at) * 1000)::bigint as created_at
  from public.alert_destinations d
  where d.type = 'webhook'
    and coalesce(btrim(d.config->>'url'), '') <> ''
    and d.config->>'hub_endpoint_id' is null
), inserted as (
  insert into public.hub_webhook_endpoints
    (id, owner, url, secret, events, description, enabled, failures, disabled_reason, created_at, updated_at)
  select endpoint_id, owner, url, secret, '["detection.created","findings.raised","reputation.changed"]',
         description, enabled, 0, null, created_at, (extract(epoch from now()) * 1000)::bigint
    from moved
  on conflict (id) do nothing
  returning id
)
update public.alert_destinations d
   set config = (d.config - 'secret') || jsonb_build_object('hub_endpoint_id', m.endpoint_id)
  from moved m
 where d.id = m.dest_id
   and m.endpoint_id in (select id from inserted);
