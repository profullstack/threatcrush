-- GitHub App installations and the scans they trigger.
--
-- Companion to 20260821170000_github_marketplace.sql. That migration covers
-- billing (who bought which plan); this one covers the product (who installed
-- the app, on which repositories, and what the scanner found).
--
-- Three tables:
--
--   github_installations             one row per installation. GitHub's
--                                    installation_id is the key.
--   github_installation_repositories the repositories an installation can see.
--   github_repo_scans                one row per scan run, with its findings
--                                    inline as jsonb.
--
-- Findings live as jsonb rather than a fourth table on purpose. They are only
-- ever read as a whole scan, never queried across scans, and the shape is
-- `ScanFinding` from @threatcrush/scan — which changes when the rules change.
-- A relational mirror of it would need a migration every time a rule grew a
-- field, to buy a query nobody runs.
--
-- Written exclusively by the service role from the webhook and scan routes.
-- RLS is enabled with no policies, matching the marketplace tables: a
-- customer's private-repo findings must not be reachable from client code even
-- by accident. The resulting `rls_enabled_no_policy` advisor lint is expected.

create table if not exists public.github_installations (
  id uuid primary key default gen_random_uuid(),

  -- GitHub's numeric installation id, stable for the life of the install.
  installation_id bigint not null unique,

  -- The account the app is installed on. The login can be renamed, so the
  -- numeric id is the durable identifier and the login is display only.
  account_id bigint,
  account_login text,
  account_type text,

  -- 'all' or 'selected' — whether the installer granted every repository.
  repository_selection text,

  -- Permissions actually granted, which can lag the app's current manifest
  -- until the account owner accepts a permissions update.
  permissions jsonb not null default '{}'::jsonb,
  events jsonb not null default '[]'::jsonb,

  sender_login text,

  -- 'active' once installed, 'suspended' while suspended, 'deleted' after
  -- uninstall. Rows are kept after uninstall: the findings are still the
  -- customer's, and a reinstall should not look like a first install.
  status text not null default 'active',

  installed_at timestamptz not null default now(),
  suspended_at timestamptz,
  deleted_at timestamptz,

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.github_installation_repositories (
  id uuid primary key default gen_random_uuid(),

  installation_id bigint not null
    references public.github_installations (installation_id) on delete cascade,

  repo_id bigint not null,
  full_name text not null,
  private boolean not null default false,
  default_branch text,

  -- Cleared when the repository is removed from the installation, rather than
  -- deleted, so a scan row still resolves to a name.
  removed_at timestamptz,

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  unique (installation_id, repo_id)
);

create table if not exists public.github_repo_scans (
  id uuid primary key default gen_random_uuid(),

  installation_id bigint not null
    references public.github_installations (installation_id) on delete cascade,

  repo_id bigint,
  full_name text not null,
  ref text,
  commit_sha text,

  -- What kicked it off: 'installation', 'repositories_added', 'push', 'manual'.
  trigger text not null,

  -- 'running' while in flight, then 'complete' or 'failed'. A row is written
  -- before the scan starts so a crashed scan is visible as a stuck 'running'
  -- rather than vanishing.
  status text not null default 'running',
  error text,

  files_considered integer not null default 0,
  files_scanned integer not null default 0,
  findings_count integer not null default 0,

  -- Highest severity present, or null for a clean scan.
  peak_severity text,

  -- True when a cap or GitHub's tree truncation cut the scan short. Kept
  -- alongside the reason so a partial scan can never be reported as clean.
  truncated boolean not null default false,
  truncation_reason text,

  findings jsonb not null default '[]'::jsonb,

  started_at timestamptz not null default now(),
  finished_at timestamptz,

  created_at timestamptz not null default now()
);

create index if not exists github_installation_repositories_installation_idx
  on public.github_installation_repositories (installation_id);

create index if not exists github_repo_scans_installation_idx
  on public.github_repo_scans (installation_id, started_at desc);

-- The dashboard reads "latest scan for this repository", which is this index
-- read backwards rather than a sort of every scan the repo ever had.
create index if not exists github_repo_scans_full_name_idx
  on public.github_repo_scans (full_name, started_at desc);

alter table public.github_installations enable row level security;
alter table public.github_installation_repositories enable row level security;
alter table public.github_repo_scans enable row level security;

-- No policies, deliberately. Service role bypasses RLS; anon and authenticated
-- get nothing. See the header comment.
