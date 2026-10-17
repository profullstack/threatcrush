-- Ban candidates: every address the fleet banned, aggregated per address with
-- its evidence, for nichedb.dev/traffic to review and publish.
--
-- This is the input to a human review, never a public list. It leaves out what
-- must never be published even as a candidate:
--   * private, loopback, link-local and CGNAT space
--   * our own servers (servers.ip_address / servers.public_ip)
--   * anything on an org allowlist (ip or cidr)
--   * addresses whose only offence was hammering a paywall or a quoted
--     user agent: the 402 swarm is the paywall working, not an attack
-- Bans recorded without a rule id carry it in the reason ("Attack
-- [PATH_TRAVERSAL]: GET /.env"), so the rule and the path are recovered from it.

create or replace function public.try_inet(value text)
returns inet language plpgsql immutable as $$
begin
  return value::inet;
exception when others then
  return null;
end
$$;

create index if not exists idx_remediation_block_created
  on public.remediation_actions (created_at)
  where action_type = 'block';

create or replace function public.ban_candidates(p_after text default null, p_limit int default 1000)
returns table (
  ip text,
  first_seen timestamptz,
  last_seen timestamptz,
  blocks int,
  servers int,
  rules text[],
  max_severity text,
  titles text[],
  paths text[],
  score int
)
language sql stable as $$
  with b as (
    select
      public.try_inet(r.target_value) as addr,
      r.server_id,
      r.created_at,
      coalesce(
        r.metadata->>'rule_id',
        d.rule_id,
        'attack-' || lower(substring(coalesce(r.metadata->>'reason', d.title) from 'Attack \[([A-Za-z_]+)\]'))
      ) as rule,
      coalesce(r.metadata->>'reason', d.title) as reason,
      d.severity
    from public.remediation_actions r
    left join public.detections d on d.id = r.detection_id
    where r.action_type = 'block'
      and r.created_at > now() - interval '90 days'
  ), agg as (
    select
      addr,
      min(created_at) as first_seen,
      max(created_at) as last_seen,
      count(*)::int as blocks,
      count(distinct server_id)::int as servers,
      array_remove(array_agg(distinct rule), null) as rules,
      (array_agg(severity order by case severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'low' then 3 else 4 end))[1] as max_severity,
      (array_remove(array_agg(distinct left(reason, 200)), null))[1:5] as titles,
      (array_remove(array_agg(distinct substring(reason from '(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) (\S+)')), null))[1:5] as paths
    from b
    where addr is not null
    group by addr
  )
  select
    host(a.addr) as ip,
    a.first_seen,
    a.last_seen,
    a.blocks,
    a.servers,
    a.rules,
    a.max_severity,
    a.titles,
    a.paths,
    (least(a.servers, 5) * 20
      + least(a.blocks, 20) * 2
      + least(cardinality(a.rules), 4) * 5
      + case when a.rules && array['web-sqli-attack', 'web-xss-attack', 'exploit-probe-pattern', 'web-path-traversal', 'ssh-brute-force']
             or exists (select 1 from unnest(a.rules) x where x like 'attack-%') then 20 else 0 end)::int as score
  from agg a
  where not (a.addr <<= any (array['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '0.0.0.0/8',
                                   '100.64.0.0/10', '169.254.0.0/16', '224.0.0.0/3', '::1/128', 'fc00::/7',
                                   'fe80::/10', 'ff00::/8']::inet[]))
    and not exists (
      select 1 from public.servers s
      where public.try_inet(s.ip_address) = a.addr or public.try_inet(s.public_ip) = a.addr
    )
    and not exists (
      select 1 from public.allowlists al
      where al.type in ('ip', 'cidr') and a.addr <<= public.try_inet(al.value)
    )
    and not (a.rules <@ array['paywall-hammering', 'quoted-user-agent']::text[])
    and (p_after is null or a.addr > public.try_inet(p_after))
  order by a.addr
  limit least(greatest(p_limit, 1), 5000)
$$;

revoke all on function public.ban_candidates(text, int) from public, anon, authenticated;
revoke all on function public.try_inet(text) from public, anon, authenticated;
grant execute on function public.ban_candidates(text, int) to service_role;
grant execute on function public.try_inet(text) to service_role;
