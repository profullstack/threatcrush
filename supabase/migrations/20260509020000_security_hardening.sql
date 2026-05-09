-- Security hardening for Supabase linter warnings:
--   * function_search_path_mutable
--   * anon_security_definer_function_executable
--   * authenticated_security_definer_function_executable
--   * rls_policy_always_true (INSERT)

-- ─── 1. Lock down function search_path on all 5 flagged functions ───
-- Empty search_path forces fully-qualified references and prevents
-- search-path hijacking by callers. pg_catalog is always implicitly
-- searched, so built-ins like now() still resolve.

create or replace function public.handle_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create or replace function public.properties_touch_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create or replace function public.handle_new_organization()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.organization_members (org_id, user_id, role)
  values (new.id, new.created_by, 'owner')
  on conflict (org_id, user_id) do nothing;
  return new;
end;
$$;

create or replace function public.claim_next_property_run(p_worker_id text, p_org_ids uuid[])
returns setof public.property_runs
language plpgsql
security definer
set search_path = ''
as $$
declare
  claimed uuid;
begin
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
        started_at = now()
    where id = claimed;

  return query select * from public.property_runs where id = claimed;
end;
$$;

create or replace function public.bump_outrank_integration(integration_id uuid)
returns void
language sql
security definer
set search_path = ''
as $$
  update public.outrank_integrations
     set last_used_at = now(),
         request_count = request_count + 1
   where id = integration_id;
$$;

-- ─── 2. Revoke PUBLIC execute on SECURITY DEFINER functions ───
-- These are called server-side via service_role only; anon/authenticated
-- have no business invoking them through PostgREST RPC.
-- Trigger functions still fire regardless of EXECUTE perms.

revoke execute on function public.handle_new_organization() from public, anon, authenticated;
revoke execute on function public.claim_next_property_run(text, uuid[]) from public, anon, authenticated;
revoke execute on function public.bump_outrank_integration(uuid) from public, anon, authenticated;

grant execute on function public.claim_next_property_run(text, uuid[]) to service_role;
grant execute on function public.bump_outrank_integration(uuid) to service_role;
-- handle_new_organization runs from a trigger, doesn't need any EXECUTE grant.

-- ─── 3. Tighten always-true INSERT policies ───

-- contact_requests: validate non-empty + reasonable lengths + email shape
drop policy if exists "Allow anonymous inserts" on public.contact_requests;
create policy "Anonymous can submit contact requests"
  on public.contact_requests
  for insert
  with check (
    char_length(name) between 1 and 200
    and char_length(email) between 3 and 254
    and email like '%_@_%.__%'
    and char_length(message) between 1 and 10000
    and (company is null or char_length(company) <= 200)
    and (topic is null or char_length(topic) <= 100)
  );

-- waitlist: validate email shape + cap length
drop policy if exists "Allow anonymous inserts" on public.waitlist;
create policy "Anonymous can join waitlist"
  on public.waitlist
  for insert
  with check (
    char_length(email) between 3 and 254
    and email like '%_@_%.__%'
  );

-- whitepaper_leads: validate non-empty name + email shape
drop policy if exists "Allow anonymous inserts" on public.whitepaper_leads;
create policy "Anonymous can request whitepaper"
  on public.whitepaper_leads
  for insert
  with check (
    char_length(name) between 1 and 200
    and char_length(email) between 3 and 254
    and email like '%_@_%.__%'
    and (company is null or char_length(company) <= 200)
  );

-- user_profiles: restrict insert to service_role explicitly
drop policy if exists "Service role can insert profiles" on public.user_profiles;
create policy "Service role can insert profiles"
  on public.user_profiles
  for insert
  with check (auth.role() = 'service_role');
