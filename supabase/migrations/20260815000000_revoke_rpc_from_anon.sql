-- Follow-up to 20260814000000 / 20260814000200.
--
-- Those migrations used `revoke all on function ... from public` and then
-- granted to service_role, on the assumption that this left nobody else able
-- to call them. It does not. Supabase grants EXECUTE to `anon` and
-- `authenticated` explicitly, and revoking from PUBLIC does not remove an
-- explicit grant to a named role — so both functions stayed reachable over
-- PostgREST at /rest/v1/rpc/<name>.
--
-- The consequence for increment_module_downloads was that an unauthenticated
-- caller could inflate any module's download count at will, which is the same
-- integrity problem TC-24 set out to fix, reached through a different door.

revoke execute on function public.increment_module_downloads(uuid) from anon, authenticated;

-- Trigger function: never meant to be callable directly by anyone.
revoke execute on function public.guard_privileged_profile_columns() from anon, authenticated;

-- current_user_is_admin stays executable by `authenticated`, because the RLS
-- policies on user_profiles call it and policy predicates run as the invoking
-- role. `anon` has no auth.uid() so it can only ever get false, but it has no
-- reason to call it either.
revoke execute on function public.current_user_is_admin() from anon;
