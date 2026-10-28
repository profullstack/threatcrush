-- Auto-defence: ban SSH from Tor exits (daemon rule ssh-from-tor).
-- On by default; an org owner/admin may switch it off in Organization settings.
-- Daemons read it from GET /api/orgs/[id] unless [remediation] block_tor_ssh
-- is set in their own config.
alter table public.organizations
  add column if not exists block_tor_ssh boolean not null default true;
