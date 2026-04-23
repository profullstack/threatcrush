create table if not exists public.contact_requests (
  id uuid default gen_random_uuid() primary key,
  name text not null,
  email text not null,
  company text,
  message text not null,
  topic text default 'general',
  handled boolean default false,
  created_at timestamptz default now()
);

create index if not exists idx_contact_requests_email
  on public.contact_requests (email);
create index if not exists idx_contact_requests_handled
  on public.contact_requests (handled);

alter table public.contact_requests enable row level security;

create policy "Allow anonymous inserts" on public.contact_requests
  for insert
  with check (true);

create policy "Service role can read" on public.contact_requests
  for select
  using (auth.role() = 'service_role');
