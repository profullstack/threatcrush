alter table public.psa_integrations
  drop constraint if exists psa_integrations_provider_check;
alter table public.psa_integrations
  add constraint psa_integrations_provider_check check (provider in ('halopsa', 'connectwise', 'autotask'));

alter table public.psa_ticket_links
  alter column incident_id drop not null,
  add column if not exists detection_id uuid references public.detections(id) on delete cascade;

alter table public.psa_ticket_links
  drop constraint if exists psa_ticket_links_integration_id_incident_id_key,
  add constraint psa_ticket_links_exactly_one_subject check (num_nonnulls(incident_id, detection_id) = 1);

create unique index if not exists psa_ticket_links_incident_unique
  on public.psa_ticket_links (integration_id, incident_id) where incident_id is not null;
create unique index if not exists psa_ticket_links_detection_unique
  on public.psa_ticket_links (integration_id, detection_id) where detection_id is not null;

create index if not exists psa_ticket_links_detection_recent
  on public.psa_ticket_links (integration_id, detection_id, updated_at desc)
  where detection_id is not null;
