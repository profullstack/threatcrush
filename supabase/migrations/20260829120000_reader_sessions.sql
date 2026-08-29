-- Engagement tracking for the on-site guide reader (/read/[slug]).
--
-- The old flow gated the whitepaper behind a form, so the only thing we ever
-- learned about a lead was that they wanted the PDF. The reader is ungated, so
-- engagement is what qualifies the lead instead: how far they read, how long
-- they stayed, and what they scored on the readiness checklist.

create table if not exists public.reader_sessions (
  id uuid default gen_random_uuid() primary key,
  session_id text not null,
  slug text not null default 'ctem-guide',

  -- Furthest scroll depth reached, 0-100. Monotonic: updates never lower it.
  read_percent smallint not null default 0,
  -- Wall-clock seconds with the tab focused.
  seconds_engaged integer not null default 0,
  -- Deepest section id the reader reached, for spotting where people drop off.
  furthest_section text,
  completed boolean not null default false,

  -- Checklist results, present only once the reader scores themselves.
  checklist_score smallint,
  checklist_band text,
  checklist_answers jsonb,

  referrer text,
  utm_source text,
  utm_medium text,
  utm_campaign text,
  utm_content text,
  utm_term text,

  ip_address text,
  user_agent text,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),

  constraint reader_sessions_session_id_slug_key unique (session_id, slug),
  constraint reader_sessions_read_percent_range check (read_percent between 0 and 100),
  constraint reader_sessions_checklist_score_range
    check (checklist_score is null or checklist_score between 0 and 100)
);

create index if not exists idx_reader_sessions_slug_created
  on public.reader_sessions (slug, created_at desc);
create index if not exists idx_reader_sessions_session_id
  on public.reader_sessions (session_id);
-- Partial: the qualified-lead view only ever looks at scored sessions.
create index if not exists idx_reader_sessions_scored
  on public.reader_sessions (checklist_score desc)
  where checklist_score is not null;

alter table public.reader_sessions enable row level security;

-- Anonymous readers write their own progress; nobody but the service role reads it.
create policy "Allow anonymous inserts" on public.reader_sessions
  for insert
  with check (true);

create policy "Service role can read" on public.reader_sessions
  for select
  using (auth.role() = 'service_role');

-- Carry engagement onto the lead row so sales sees the score, not just the email.
alter table public.whitepaper_leads
  add column if not exists session_id text,
  add column if not exists read_percent smallint,
  add column if not exists checklist_score smallint,
  add column if not exists checklist_band text,
  add column if not exists checklist_answers jsonb;

create index if not exists idx_whitepaper_leads_session_id
  on public.whitepaper_leads (session_id);

-- Progress beacons are fire-and-forget and can arrive out of order (sendBeacon
-- gives no ordering guarantee, and a backgrounded tab flushes late). A plain
-- upsert would let a stale 25% overwrite a live 80%, so depth and time only
-- ever ratchet upwards and `completed` is sticky.
create or replace function public.record_reader_progress(
  p_session_id text,
  p_slug text,
  p_read_percent smallint,
  p_seconds_engaged integer,
  p_furthest_section text,
  p_completed boolean,
  p_referrer text default null,
  p_utm_source text default null,
  p_utm_medium text default null,
  p_utm_campaign text default null,
  p_utm_content text default null,
  p_utm_term text default null,
  p_ip_address text default null,
  p_user_agent text default null
) returns void
language sql
security definer
set search_path = public
as $$
  insert into public.reader_sessions (
    session_id, slug, read_percent, seconds_engaged, furthest_section, completed,
    referrer, utm_source, utm_medium, utm_campaign, utm_content, utm_term,
    ip_address, user_agent
  )
  values (
    p_session_id, p_slug, greatest(p_read_percent, 0), greatest(p_seconds_engaged, 0),
    p_furthest_section, coalesce(p_completed, false),
    p_referrer, p_utm_source, p_utm_medium, p_utm_campaign, p_utm_content, p_utm_term,
    p_ip_address, p_user_agent
  )
  on conflict (session_id, slug) do update set
    read_percent     = greatest(reader_sessions.read_percent, excluded.read_percent),
    seconds_engaged  = greatest(reader_sessions.seconds_engaged, excluded.seconds_engaged),
    -- Only advance the section marker when this beacon is actually deeper.
    furthest_section = case
                         when excluded.read_percent >= reader_sessions.read_percent
                           then coalesce(excluded.furthest_section, reader_sessions.furthest_section)
                         else reader_sessions.furthest_section
                       end,
    completed        = reader_sessions.completed or excluded.completed,
    referrer         = coalesce(reader_sessions.referrer, excluded.referrer),
    updated_at       = now();
$$;

-- Written to only by the API route, which holds the service-role key.
revoke all on function public.record_reader_progress(
  text, text, smallint, integer, text, boolean,
  text, text, text, text, text, text, text, text
) from public, anon, authenticated;

-- Records the checklist result against an existing session row.
create or replace function public.record_reader_checklist(
  p_session_id text,
  p_slug text,
  p_score smallint,
  p_band text,
  p_answers jsonb
) returns void
language sql
security definer
set search_path = public
as $$
  insert into public.reader_sessions (
    session_id, slug, checklist_score, checklist_band, checklist_answers
  )
  values (p_session_id, p_slug, p_score, p_band, p_answers)
  on conflict (session_id, slug) do update set
    checklist_score   = excluded.checklist_score,
    checklist_band    = excluded.checklist_band,
    checklist_answers = excluded.checklist_answers,
    updated_at        = now();
$$;

revoke all on function public.record_reader_checklist(text, text, smallint, text, jsonb)
  from public, anon, authenticated;
