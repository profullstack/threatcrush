-- GitHub Marketplace plan-change webhook.
--
-- The Marketplace listing posts `marketplace_purchase` events to
-- /api/webhooks/github/marketplace whenever a customer buys, upgrades,
-- downgrades or cancels a plan. See
-- https://docs.github.com/en/apps/github-marketplace/listing-an-app-on-github-marketplace/configuring-a-webhook-to-notify-you-of-plan-changes
--
-- Two tables, on purpose:
--
--   github_marketplace_purchases  the CURRENT subscription per GitHub
--                                 account. One row per account, upserted.
--   github_marketplace_events     every delivery, raw. GitHub does not
--                                 resend failed deliveries, so the raw log
--                                 is the only way to replay a bad deploy.
--
-- Both are written exclusively by the service role from the webhook route.
-- RLS is enabled with no policies, so anon and authenticated cannot read a
-- customer's billing state even if a query slips into client code.

create table if not exists public.github_marketplace_purchases (
  id uuid primary key default gen_random_uuid(),

  -- account.id is GitHub's stable numeric id. The login can be renamed,
  -- so the id is the key and the login is a display convenience.
  github_account_id bigint not null unique,
  github_account_login text not null,
  github_account_type text,
  github_account_node_id text,
  organization_billing_email text,

  plan_id bigint,
  plan_name text,
  plan_monthly_price_cents integer,
  plan_yearly_price_cents integer,
  billing_cycle text,
  unit_count integer,
  on_free_trial boolean not null default false,
  free_trial_ends_on timestamptz,
  next_billing_date timestamptz,

  -- active | cancelled | pending_change
  status text not null default 'active',

  -- Set by pending_change, cleared by pending_change_cancelled or by the
  -- `changed` event that actually applies it.
  pending_plan_id bigint,
  pending_plan_name text,
  pending_effective_date timestamptz,

  sender_login text,

  -- The effective_date of the most recent event applied to this row.
  -- Guards against out-of-order delivery: an older event must not
  -- overwrite a newer state.
  effective_date timestamptz,
  last_action text,

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_gh_marketplace_purchases_login
  on public.github_marketplace_purchases (github_account_login);

create index if not exists idx_gh_marketplace_purchases_status
  on public.github_marketplace_purchases (status);

create table if not exists public.github_marketplace_events (
  id uuid primary key default gen_random_uuid(),

  -- X-GitHub-Delivery. Unique so a retry of the same delivery is a no-op
  -- rather than a duplicate row.
  delivery_id text unique,

  action text not null,
  github_account_id bigint,
  github_account_login text,
  effective_date timestamptz,

  -- Whether this delivery changed the purchases row, and why not if it did
  -- not. Makes "the webhook fired but nothing happened" answerable.
  applied boolean not null default false,
  skip_reason text,

  payload jsonb not null,
  received_at timestamptz not null default now()
);

create index if not exists idx_gh_marketplace_events_received
  on public.github_marketplace_events (received_at desc);

create index if not exists idx_gh_marketplace_events_account
  on public.github_marketplace_events (github_account_id);

alter table public.github_marketplace_purchases enable row level security;
alter table public.github_marketplace_events enable row level security;

-- No policies: service role only. Deliberate.
revoke all on public.github_marketplace_purchases from anon, authenticated;
revoke all on public.github_marketplace_events from anon, authenticated;
