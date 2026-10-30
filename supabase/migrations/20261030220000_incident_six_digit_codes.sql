-- Random, typeable six-digit incident codes are globally unique.
-- Codes are locators only: each resolver still authenticates and checks the
-- caller's incident read permission.

alter table public.incidents add column if not exists human_code text;

do $$
declare
  incident record;
  candidate text;
  attempts integer;
begin
  for incident in
    select id, org_id from public.incidents where human_code is null order by org_id, id
  loop
    attempts := 0;
    loop
      candidate := lpad(floor(random() * 1000000)::integer::text, 6, '0');
      exit when not exists (
        select 1 from public.incidents
         where human_code = candidate
      );
      attempts := attempts + 1;
      if attempts >= 1000 then
        raise exception 'Could not allocate a unique six-digit code for incident %', incident.id;
      end if;
    end loop;
    update public.incidents set human_code = candidate where id = incident.id;
  end loop;
end
$$;

alter table public.incidents alter column human_code set not null;
alter table public.incidents add constraint incidents_human_code_six_digits_check check (human_code ~ '^[0-9]{6}$');
create unique index incidents_human_code_key on public.incidents (human_code);
