-- Add Crawlproof autoblog support alongside the existing Outrank integration.
--
-- The outrank_integrations table is the right shape for any per-source
-- bearer-token store, so we extend it with a kind column rather than
-- creating a parallel table. blog_posts.source already supports
-- arbitrary string values; ingested Crawlproof articles will land with
-- source = 'crawlproof'.
--
-- See https://crawlproof.com/docs/autoblog-webhook for the payload
-- contract. The new /api/webhooks/crawlproof route consumes it.

alter table public.outrank_integrations
  add column if not exists kind text not null default 'outrank';

-- Constrain the kind value. Drop first in case the constraint already
-- exists from a partial earlier run.
alter table public.outrank_integrations
  drop constraint if exists outrank_integrations_kind_check;

alter table public.outrank_integrations
  add constraint outrank_integrations_kind_check
  check (kind in ('outrank', 'crawlproof'));

create index if not exists idx_outrank_integrations_kind
  on public.outrank_integrations (kind);
