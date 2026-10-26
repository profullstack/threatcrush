-- The shared @profullstack/profile fields on public.user_profiles (keyed by id,
-- the auth user id). The table is owner-only (plus admins) under RLS and the
-- app reads it through the service role, so the fields live here rather than
-- in a separate private table.
--
-- Apply by hand against the dev2 self-hosted database, one file at a time
-- (`docker exec -i threatcrush-com-supabase-db psql -U postgres -d postgres -1 < this file`,
-- then `notify pgrst, 'reload schema'`), or with the "Migrate dev2 database"
-- workflow in apply mode. Additive only, so it is safe before the deploy.
--
-- email and updated_at already exist. Nothing is renamed or dropped;
-- display_name stays as it is.

alter table public.user_profiles add column if not exists first_name text;
alter table public.user_profiles add column if not exists last_name text;
alter table public.user_profiles add column if not exists company_domain text;
alter table public.user_profiles add column if not exists job_title text;
alter table public.user_profiles add column if not exists linkedin_url text;

create index if not exists user_profiles_email_lower on public.user_profiles (lower(email));

-- One-time backfill, idempotent: split display_name into first/last only when
-- it is exactly two capitalised words of letters ("Ada Lovelace"). Handles,
-- emails, single words and agent or company names are left alone. Never
-- overwrites a value already present.
update public.user_profiles
   set first_name = coalesce(first_name, split_part(btrim(display_name), ' ', 1)),
       last_name  = coalesce(last_name, split_part(btrim(display_name), ' ', 2))
 where (first_name is null or last_name is null)
   and display_name is not null
   and btrim(display_name) ~ '^[[:upper:]][[:lower:]''’-]+ [[:upper:]][[:lower:]''’-]+$'
   and display_name !~* '\m(agent|bot|ai|assistant|team|labs?|security|inc|llc)\M';
