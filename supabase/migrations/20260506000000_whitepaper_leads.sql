create table if not exists public.whitepaper_leads (
  id uuid default gen_random_uuid() primary key,
  name text not null,
  email text not null,
  company text,
  role text,
  team_size text,
  source text,
  utm_source text,
  utm_medium text,
  utm_campaign text,
  utm_content text,
  utm_term text,
  whitepaper_slug text not null default 'ctem-guide',
  consent_marketing boolean default true,
  ip_address text,
  user_agent text,
  created_at timestamptz default now()
);

create index if not exists idx_whitepaper_leads_email
  on public.whitepaper_leads (email);
create index if not exists idx_whitepaper_leads_created_at
  on public.whitepaper_leads (created_at desc);
create index if not exists idx_whitepaper_leads_slug
  on public.whitepaper_leads (whitepaper_slug);

alter table public.whitepaper_leads enable row level security;

create policy "Allow anonymous inserts" on public.whitepaper_leads
  for insert
  with check (true);

create policy "Service role can read" on public.whitepaper_leads
  for select
  using (auth.role() = 'service_role');
