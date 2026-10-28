-- Merged blog posts: a retired slug answers 301 to the post it was folded into.
-- Also how the autoblog receivers recognise a retired topic coming back.
create table if not exists public.blog_redirects (
  from_slug text primary key,
  to_slug text not null,
  reason text,
  created_at timestamptz not null default now(),
  check (from_slug <> to_slug)
);

-- Service role only (the app reads it with the admin client).
alter table public.blog_redirects enable row level security;
revoke all on public.blog_redirects from anon, authenticated;
