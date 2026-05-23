-- Per-user module installs + settings.
--
-- Public module rows describe what can be installed and which config fields a
-- user may provide. User values live outside the catalog: non-secret values in
-- JSONB, secrets encrypted as an AES-GCM blob by the web/API layer.

alter table public.modules
  add column if not exists npm_package text,
  add column if not exists tarball_url text,
  add column if not exists config_schema jsonb not null default '[]'::jsonb,
  add column if not exists config_notes text;

create table if not exists public.user_installed_modules (
  user_id uuid not null references auth.users(id) on delete cascade,
  module_id uuid not null references public.modules(id) on delete cascade,
  module_slug text not null,
  version text not null,
  status text not null default 'active',
  installed_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (user_id, module_id),
  check (status in ('active', 'disabled', 'removed'))
);

create index if not exists user_installed_modules_user_idx
  on public.user_installed_modules (user_id, installed_at desc);

create index if not exists user_installed_modules_slug_idx
  on public.user_installed_modules (module_slug);

alter table public.user_installed_modules enable row level security;

drop policy if exists "Users can read their own installed modules" on public.user_installed_modules;
create policy "Users can read their own installed modules"
  on public.user_installed_modules
  for select
  using (auth.uid() = user_id);

drop policy if exists "Users can manage their own installed modules" on public.user_installed_modules;
create policy "Users can manage their own installed modules"
  on public.user_installed_modules
  for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "Service role full access on user_installed_modules" on public.user_installed_modules;
create policy "Service role full access on user_installed_modules"
  on public.user_installed_modules
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

create table if not exists public.user_settings (
  user_id uuid primary key references auth.users(id) on delete cascade,
  payload_plain jsonb not null default '{}'::jsonb,
  payload_secret_ciphertext text,
  payload_secret_iv text,
  payload_secret_tag text,
  updated_at timestamptz not null default now()
);

create index if not exists user_settings_updated_idx
  on public.user_settings (updated_at desc);

alter table public.user_settings enable row level security;

drop policy if exists "Users can read their own settings" on public.user_settings;
create policy "Users can read their own settings"
  on public.user_settings
  for select
  using (auth.uid() = user_id);

drop policy if exists "Users can manage their own settings" on public.user_settings;
create policy "Users can manage their own settings"
  on public.user_settings
  for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "Service role full access on user_settings" on public.user_settings;
create policy "Service role full access on user_settings"
  on public.user_settings
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

with upserted as (
  insert into public.modules (
    name,
    slug,
    display_name,
    description,
    long_description,
    author_name,
    author_url,
    homepage_url,
    git_url,
    license,
    pricing_type,
    category,
    tags,
    keywords,
    version,
    min_threatcrush_version,
    os_support,
    capabilities,
    npm_package,
    config_schema,
    config_notes,
    verified,
    featured,
    published
  )
  values (
    'deepsec',
    'deepsec',
    'DeepSec',
    'Agent-powered vulnerability scanner for on-demand review of large codebases.',
    $md$DeepSec is Vercel Labs' agent-powered vulnerability scanner. It runs in the repository you want to scan, finds candidate security issues quickly, then uses coding agents to investigate and produce findings. Install it from npm, initialize it inside a target repo, and provide your own Vercel AI Gateway key for real scans.

## Install

```bash
npm install -g deepsec
```

Or run it directly:

```bash
npx deepsec init
cd .deepsec
pnpm install
pnpm deepsec scan
pnpm deepsec process
```

## Secrets

Set `AI_GATEWAY_API_KEY` in your ThreatCrush account settings, local shell, or CI environment. ThreatCrush never stores that key in the public module catalog.$md$,
    'Vercel Labs',
    'https://vercel.com',
    'https://github.com/vercel-labs/deepsec',
    'https://github.com/vercel-labs/deepsec',
    'Apache-2.0',
    'free',
    'scanning',
    array['ai', 'code-scanning', 'vulnerability-scanner', 'vercel', 'agent'],
    'deepsec,ai gateway,vercel,codex,claude,vulnerability scanner,code security',
    '2.0.10',
    '>=0.2.0',
    array['linux', 'darwin'],
    array['code:scan', 'ai:gateway', 'secrets:required'],
    'deepsec',
    '[
      {
        "key": "AI_GATEWAY_API_KEY",
        "label": "Vercel AI Gateway API key",
        "type": "secret",
        "scope": "global",
        "required": true,
        "placeholder": "vck_...",
        "help": "Used by DeepSec process/revalidate runs. Store a user-owned key here; do not publish it in module metadata."
      },
      {
        "key": "DEEPSEC_AGENT",
        "label": "Default agent",
        "type": "string",
        "scope": "module",
        "required": false,
        "default": "codex",
        "placeholder": "codex",
        "help": "Optional default agent for your run scripts, such as codex or claude."
      },
      {
        "key": "DEEPSEC_SANDBOX_ENABLED",
        "label": "Use Vercel Sandbox for distributed scans",
        "type": "boolean",
        "scope": "module",
        "required": false,
        "default": false,
        "help": "Enable only if you have Vercel Sandbox configured for the target workspace."
      }
    ]'::jsonb,
    'AI_GATEWAY_API_KEY is a per-user/global secret. ThreatCrush does not ship a shared Vercel key to store users.',
    true,
    true,
    true
  )
  on conflict (slug) do update set
    display_name = excluded.display_name,
    description = excluded.description,
    long_description = excluded.long_description,
    author_name = excluded.author_name,
    author_url = excluded.author_url,
    homepage_url = excluded.homepage_url,
    git_url = excluded.git_url,
    license = excluded.license,
    pricing_type = excluded.pricing_type,
    category = excluded.category,
    tags = excluded.tags,
    keywords = excluded.keywords,
    version = excluded.version,
    min_threatcrush_version = excluded.min_threatcrush_version,
    os_support = excluded.os_support,
    capabilities = excluded.capabilities,
    npm_package = excluded.npm_package,
    config_schema = excluded.config_schema,
    config_notes = excluded.config_notes,
    verified = excluded.verified,
    featured = excluded.featured,
    published = excluded.published,
    updated_at = now()
  returning id, version
)
insert into public.module_versions (module_id, version, changelog, git_tag, package_url)
select id, version, 'Initial ThreatCrush catalog listing', null, null
from upserted
on conflict (module_id, version) do nothing;
