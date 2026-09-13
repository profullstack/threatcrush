-- Per-installation announce switch for the OpenThreat descriptor.
-- Created: 2026-09-13
--
-- threatcrush.com/discovery publishes the findings the GitHub App found in
-- PUBLIC repositories, as an OpenThreat descriptor at
-- /.well-known/openthreat.json. Private repositories are never published and
-- nothing about organizations, servers, properties or detections is either.
-- This column lets the person who installed the app keep their public
-- repositories out of that list too. Announcements are ON by default; the
-- switch lives in the app settings for the installation.

alter table public.github_installations
  add column if not exists announce boolean not null default true;

comment on column public.github_installations.announce is
  'When true, findings from this installation''s PUBLIC repositories are published on threatcrush.com/discovery (OpenThreat). Default on; the installer can turn it off in app settings.';
