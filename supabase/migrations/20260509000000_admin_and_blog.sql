-- Admin role + blog publishing integrations (Outrank webhook)

-- 1. is_admin flag on user_profiles
alter table public.user_profiles
  add column if not exists is_admin boolean not null default false;

create index if not exists idx_user_profiles_is_admin
  on public.user_profiles (is_admin)
  where is_admin = true;

-- Admins can read & update any profile
drop policy if exists "Admins can read all profiles" on public.user_profiles;
create policy "Admins can read all profiles" on public.user_profiles
  for select
  using (
    exists (
      select 1 from public.user_profiles p
      where p.id = auth.uid() and p.is_admin = true
    )
  );

drop policy if exists "Admins can update all profiles" on public.user_profiles;
create policy "Admins can update all profiles" on public.user_profiles
  for update
  using (
    exists (
      select 1 from public.user_profiles p
      where p.id = auth.uid() and p.is_admin = true
    )
  );

-- 2. outrank_integrations: stores webhook access tokens
create table if not exists public.outrank_integrations (
  id uuid default gen_random_uuid() primary key,
  name text not null,
  access_token text not null unique,
  created_by uuid references public.user_profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  request_count integer not null default 0
);

create index if not exists idx_outrank_integrations_token
  on public.outrank_integrations (access_token);

alter table public.outrank_integrations enable row level security;

-- Only service role touches this table from app code; admins read via service-role API.
create policy "Service role full access on outrank_integrations"
  on public.outrank_integrations
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- 3. blog_posts: ingested articles
create table if not exists public.blog_posts (
  id uuid default gen_random_uuid() primary key,
  source text not null default 'outrank',
  source_id text,
  slug text not null,
  title text not null,
  content_markdown text,
  content_html text,
  meta_description text,
  image_url text,
  tags text[] not null default '{}',
  source_created_at timestamptz,
  published_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (source, source_id)
);

create unique index if not exists idx_blog_posts_slug on public.blog_posts (slug);
create index if not exists idx_blog_posts_published_at on public.blog_posts (published_at desc);
create index if not exists idx_blog_posts_tags on public.blog_posts using gin (tags);

alter table public.blog_posts enable row level security;

-- Public read access — blog is public content
create policy "Anyone can read blog posts"
  on public.blog_posts
  for select
  using (true);

-- Only service role writes
create policy "Service role can write blog posts"
  on public.blog_posts
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- 4. Atomic counter bump for the outrank webhook
create or replace function public.bump_outrank_integration(integration_id uuid)
returns void
language sql
security definer
as $$
  update public.outrank_integrations
     set last_used_at = now(),
         request_count = request_count + 1
   where id = integration_id;
$$;
revoke all on function public.bump_outrank_integration(uuid) from public;
grant execute on function public.bump_outrank_integration(uuid) to service_role;
