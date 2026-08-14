-- TC-01: any authenticated user could PATCH their own user_profiles row and set
-- is_admin = true, because "Users can update own profile" had a USING clause but
-- no WITH CHECK. The same hole let a user self-grant license_status / *_verified,
-- which are the gates the payment flow reads.
--
-- The obvious fix — WITH CHECK (is_admin = (select is_admin from user_profiles ...))
-- — makes the policy reference its own table and Postgres raises
-- "infinite recursion detected in policy for relation user_profiles".
-- So privileged columns are pinned by a BEFORE UPDATE trigger instead, which is
-- enforced no matter which policy admitted the row.

-- ─── 1. Admin check that does not recurse through RLS ───
-- security definer so the lookup bypasses the policies on user_profiles;
-- without this the admin policies below re-enter user_profiles and recurse.
create or replace function public.current_user_is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(
    (select p.is_admin from public.user_profiles p where p.id = auth.uid()),
    false
  );
$$;

revoke all on function public.current_user_is_admin() from public;
grant execute on function public.current_user_is_admin() to authenticated, service_role;

-- Rewrite the admin policies to use it (they previously self-referenced).
drop policy if exists "Admins can read all profiles" on public.user_profiles;
create policy "Admins can read all profiles" on public.user_profiles
  for select
  using (public.current_user_is_admin());

drop policy if exists "Admins can update all profiles" on public.user_profiles;
create policy "Admins can update all profiles" on public.user_profiles
  for update
  using (public.current_user_is_admin())
  with check (public.current_user_is_admin());

-- ─── 2. Give the self-update policy a WITH CHECK ───
-- Stops a user from rewriting someone else's row id in the same statement.
drop policy if exists "Users can update own profile" on public.user_profiles;
create policy "Users can update own profile"
  on public.user_profiles for update
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- ─── 3. Pin privileged columns ───
-- Columns an end user must never be able to write to their own row. Each one is
-- either a privilege grant (is_admin), an identity claim the app trusts
-- (email, *_verified), or a billing/payout field.
create or replace function public.guard_privileged_profile_columns()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  jwt_role text := current_setting('request.jwt.claims', true)::jsonb ->> 'role';
begin
  -- service_role (our server-side admin client) and direct/migration
  -- connections (no JWT at all) are trusted to write these.
  if jwt_role is null or jwt_role = 'service_role' then
    return new;
  end if;

  -- An existing admin may administer other people's profiles, but may not
  -- mint new admins from an end-user session.
  if public.current_user_is_admin() then
    new.is_admin := old.is_admin;
    return new;
  end if;

  new.is_admin := old.is_admin;
  new.email := old.email;
  new.email_verified := old.email_verified;
  new.phone_verified := old.phone_verified;
  new.license_key := old.license_key;
  new.license_status := old.license_status;
  new.referral_code := old.referral_code;
  new.referred_by := old.referred_by;
  new.total_referral_earnings_usd := old.total_referral_earnings_usd;
  return new;
end;
$$;

revoke all on function public.guard_privileged_profile_columns() from public;

drop trigger if exists guard_privileged_profile_columns on public.user_profiles;
create trigger guard_privileged_profile_columns
  before update on public.user_profiles
  for each row
  execute function public.guard_privileged_profile_columns();
