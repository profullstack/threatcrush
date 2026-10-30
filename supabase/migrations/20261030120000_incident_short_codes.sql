-- Short, readable incident links for SMS and phone paging. The code is an
-- identifier only: every lookup still authenticates and checks incident read
-- access before returning a destination.

alter table public.incidents add column if not exists short_code text;

-- Keep a short title prefix, then enough UUID characters to make collisions
-- vanishingly unlikely. The generated form is lowercase ASCII alphanumeric.
update public.incidents
   set short_code = coalesce(
         nullif(left(regexp_replace(lower(title), '[^a-z0-9]', '', 'g'), 16), ''),
         'incident'
       ) || right(replace(id::text, '-', ''), 14)
 where short_code is null;

alter table public.incidents alter column short_code set not null;
create unique index if not exists incidents_short_code_key on public.incidents (short_code);
