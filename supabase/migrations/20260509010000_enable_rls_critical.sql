-- Enable RLS on tables that were exposed via PostgREST without it.
-- All app-side access goes through service-role API routes, which bypass RLS.
-- These policies define what's visible to anon/authenticated roles via the
-- public PostgREST endpoint.

-- 1. modules — marketplace listings (published rows are public)
alter table public.modules enable row level security;

drop policy if exists "Anyone can read published modules" on public.modules;
create policy "Anyone can read published modules"
  on public.modules
  for select
  using (published = true);

drop policy if exists "Service role full access on modules" on public.modules;
create policy "Service role full access on modules"
  on public.modules
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- 2. module_versions — version metadata for published modules is public
alter table public.module_versions enable row level security;

drop policy if exists "Anyone can read versions of published modules" on public.module_versions;
create policy "Anyone can read versions of published modules"
  on public.module_versions
  for select
  using (
    exists (
      select 1 from public.modules m
      where m.id = module_versions.module_id and m.published = true
    )
  );

drop policy if exists "Service role full access on module_versions" on public.module_versions;
create policy "Service role full access on module_versions"
  on public.module_versions
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- 3. module_reviews — public reviews of published modules
alter table public.module_reviews enable row level security;

drop policy if exists "Anyone can read reviews of published modules" on public.module_reviews;
create policy "Anyone can read reviews of published modules"
  on public.module_reviews
  for select
  using (
    exists (
      select 1 from public.modules m
      where m.id = module_reviews.module_id and m.published = true
    )
  );

drop policy if exists "Service role full access on module_reviews" on public.module_reviews;
create policy "Service role full access on module_reviews"
  on public.module_reviews
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- 4. module_installs — install telemetry, not public
alter table public.module_installs enable row level security;

drop policy if exists "Service role full access on module_installs" on public.module_installs;
create policy "Service role full access on module_installs"
  on public.module_installs
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- 5. license_purchases — financial records, owner-only read
alter table public.license_purchases enable row level security;

drop policy if exists "Users can read their own license purchases" on public.license_purchases;
create policy "Users can read their own license purchases"
  on public.license_purchases
  for select
  using (auth.uid() = user_id);

drop policy if exists "Service role full access on license_purchases" on public.license_purchases;
create policy "Service role full access on license_purchases"
  on public.license_purchases
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- 6. referral_wallets — payout addresses, owner-only CRUD
alter table public.referral_wallets enable row level security;

drop policy if exists "Users can read their own wallets" on public.referral_wallets;
create policy "Users can read their own wallets"
  on public.referral_wallets
  for select
  using (auth.uid() = user_id);

drop policy if exists "Users can manage their own wallets" on public.referral_wallets;
create policy "Users can manage their own wallets"
  on public.referral_wallets
  for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "Service role full access on referral_wallets" on public.referral_wallets;
create policy "Service role full access on referral_wallets"
  on public.referral_wallets
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');
