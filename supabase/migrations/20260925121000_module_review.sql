-- Module marketplace review queue + source health.
--
-- Until now `modules.published` defaulted to true and POST /api/modules only
-- required a verified email, so anything submitted went live immediately.
-- New submissions now land as `review_status = 'pending'`, unpublished, and
-- only become public once an admin approves them.
--
-- Listings that are already live are grandfathered as approved rather than
-- silently delisted; the source health columns let an admin find the ones
-- whose source has gone away.
--
-- Additive and idempotent: safe to re-run.

alter table public.modules
  add column if not exists review_status text not null default 'pending',
  add column if not exists reviewed_by uuid references public.user_profiles(id) on delete set null,
  add column if not exists reviewed_at timestamptz,
  add column if not exists review_note text,
  add column if not exists source_status text,
  add column if not exists source_checked_at timestamptz,
  add column if not exists source_check_detail text;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'modules_review_status_check' and conrelid = 'public.modules'::regclass
  ) then
    alter table public.modules
      add constraint modules_review_status_check
      check (review_status in ('pending', 'approved', 'rejected'));
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'modules_source_status_check' and conrelid = 'public.modules'::regclass
  ) then
    alter table public.modules
      add constraint modules_source_status_check
      check (source_status is null or source_status in ('ok', 'unreachable', 'not_found'));
  end if;
end $$;

-- Grandfather the listings that are live today. `reviewed_at is null` keeps a
-- re-run from touching rows an admin has since reviewed.
update public.modules
set review_status = 'approved',
    reviewed_at = now(),
    review_note = 'Approved automatically: was already published when the review queue was introduced.'
where published = true
  and review_status = 'pending'
  and reviewed_at is null;

-- New rows are private until approved.
alter table public.modules alter column published set default false;

create index if not exists idx_modules_review_status on public.modules(review_status);

-- Public (anon) reads must follow the same rule the API does: approved AND published.
drop policy if exists "Anyone can read published modules" on public.modules;
create policy "Anyone can read published modules"
  on public.modules
  for select
  using (published = true and review_status = 'approved');

drop policy if exists "Anyone can read versions of published modules" on public.module_versions;
create policy "Anyone can read versions of published modules"
  on public.module_versions
  for select
  using (
    exists (
      select 1 from public.modules m
      where m.id = module_versions.module_id
        and m.published = true
        and m.review_status = 'approved'
    )
  );

drop policy if exists "Anyone can read reviews of published modules" on public.module_reviews;
create policy "Anyone can read reviews of published modules"
  on public.module_reviews
  for select
  using (
    exists (
      select 1 from public.modules m
      where m.id = module_reviews.module_id
        and m.published = true
        and m.review_status = 'approved'
    )
  );
