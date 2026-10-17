-- Where a server is, for the attack map: the public address its daemon's
-- heartbeat arrives from (POST /api/ingest). ip_address stays what the owner
-- typed; the map prefers public_ip and falls back to it.
alter table public.servers
  add column if not exists public_ip text;
