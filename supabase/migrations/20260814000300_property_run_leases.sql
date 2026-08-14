-- TC-16: claim_next_property_run flipped a run to 'running' and set worker_id,
-- but nothing ever expired that claim. A worker that crashed mid-run left the
-- row 'running' forever, so the property silently stopped being scanned and the
-- queue slot was never recovered.
--
-- Runs now carry a lease. Claiming takes a lease; a claim whose lease has
-- lapsed is treated as abandoned and re-queued by the same call.

alter table public.property_runs
  add column if not exists lease_expires_at timestamptz;

create index if not exists idx_property_runs_lease
  on public.property_runs (lease_expires_at)
  where status = 'running';

create or replace function public.claim_next_property_run(p_worker_id text, p_org_ids uuid[])
returns setof public.property_runs
language plpgsql
security definer
set search_path = ''
as $$
declare
  claimed uuid;
  lease_seconds constant integer := 1800; -- 30 minutes
begin
  -- Recover runs whose worker died holding the claim.
  update public.property_runs
     set status = 'queued',
         worker_id = null,
         started_at = null,
         lease_expires_at = null
   where status = 'running'
     and org_id = any(p_org_ids)
     and lease_expires_at is not null
     and lease_expires_at < now();

  select id into claimed
    from public.property_runs
    where status = 'queued'
      and org_id = any(p_org_ids)
    order by queued_at asc
    for update skip locked
    limit 1;

  if claimed is null then
    return;
  end if;

  update public.property_runs
    set status = 'running',
        worker_id = p_worker_id,
        started_at = now(),
        lease_expires_at = now() + make_interval(secs => lease_seconds)
    where id = claimed;

  return query select * from public.property_runs where id = claimed;
end;
$$;

revoke execute on function public.claim_next_property_run(text, uuid[]) from public, anon, authenticated;
grant execute on function public.claim_next_property_run(text, uuid[]) to service_role;
