-- Known IPs: the org allowlist (never-ban list every daemon pulls) gains a
-- label, where the entry came from, and the server it belongs to. Every
-- server's public IP is on it automatically, so our own boxes never ban each
-- other (dev3 was banned three times by our own fleet in Oct 2026), and an
-- admin adds the rest (office, home, VPN, CI egress).
--
-- Known is not trusted: attack traffic from a known IP is labelled as ours in
-- alerts and on the Known IPs page, because one of our addresses running
-- SQL injection is a compromised service, not noise. That is the choke point.

alter table public.allowlists
  add column if not exists label text,
  add column if not exists source text not null default 'manual',
  add column if not exists server_id uuid references public.servers(id) on delete cascade;

alter table public.allowlists drop constraint if exists allowlists_source_check;
alter table public.allowlists add constraint allowlists_source_check check (source in ('manual', 'server'));

create index if not exists allowlists_server on public.allowlists (server_id) where server_id is not null;

-- Keep each server's public IP on its org's list. A manual row for the same
-- address is kept (its label and note win) and just gains the server link.
create or replace function public.sync_server_known_ip() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.public_ip is null or new.org_id is null then
    return new;
  end if;
  -- The server moved: drop its old automatic entry.
  delete from allowlists
   where server_id = new.id and source = 'server' and value <> new.public_ip;
  insert into allowlists (organization_id, type, value, note, label, source, server_id)
  values (new.org_id, 'ip', new.public_ip, 'Added automatically: this server''s public IP', new.name, 'server', new.id)
  on conflict (organization_id, type, value) do update
    set server_id = coalesce(allowlists.server_id, excluded.server_id),
        label = coalesce(allowlists.label, excluded.label);
  return new;
end;
$$;

revoke all on function public.sync_server_known_ip() from public;
revoke execute on function public.sync_server_known_ip() from anon, authenticated;

drop trigger if exists servers_known_ip on public.servers;
create trigger servers_known_ip
  after insert or update of public_ip, org_id on public.servers
  for each row execute function public.sync_server_known_ip();

-- Backfill: every server that already reported a public IP.
insert into public.allowlists (organization_id, type, value, note, label, source, server_id)
select s.org_id, 'ip', s.public_ip, 'Added automatically: this server''s public IP', s.name, 'server', s.id
  from public.servers s
 where s.public_ip is not null and s.org_id is not null
on conflict (organization_id, type, value) do update
  set server_id = coalesce(allowlists.server_id, excluded.server_id),
      label = coalesce(allowlists.label, excluded.label);

-- detections.source_ip is free text from daemons; public.try_inet (already in
-- the schema) casts it without ever failing.

-- Activity per known entry over the last p_days: attack detections whose
-- source is that address or inside that range, anywhere in the org.
create or replace function public.known_ip_activity(p_org uuid, p_days int default 7)
returns table (entry_id uuid, detections bigint, last_24h bigint, high_critical bigint, last_seen timestamptz, rules text[], servers text[])
language sql stable security definer set search_path = public as $$
  with entries as (
    select a.id, a.value from allowlists a
     where a.organization_id = p_org and a.type in ('ip', 'cidr')
  ), hits as (
    select e.id entry_id, d.detected_at, d.severity, d.rule_id, s.name server
      from entries e
      join detections d on d.organization_id = p_org
       and d.detected_at > now() - make_interval(days => p_days)
       and public.try_inet(d.source_ip) <<= e.value::inet
      left join servers s on s.id = d.server_id
  )
  select e.id, count(h.entry_id), count(h.entry_id) filter (where h.detected_at > now() - interval '24 hours'),
         count(h.entry_id) filter (where h.severity in ('high', 'critical')), max(h.detected_at),
         coalesce(array_agg(distinct h.rule_id) filter (where h.rule_id is not null), '{}'),
         coalesce(array_agg(distinct h.server) filter (where h.server is not null), '{}')
    from entries e left join hits h on h.entry_id = e.id
   group by e.id;
$$;

revoke all on function public.known_ip_activity(uuid, int) from public;
revoke execute on function public.known_ip_activity(uuid, int) from anon, authenticated;
