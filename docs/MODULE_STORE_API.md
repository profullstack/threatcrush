# ThreatCrush Module Store — API Reference

The Module Store is a public catalog of ThreatCrush modules. Anyone can
**list, view, install, and review** modules anonymously. **Publishing** a
module requires a verified ThreatCrush account.

This document is the canonical reference. If the routes here don't match
production, the source files under `apps/web/src/app/api/modules/` win — open
an issue.

- **Base URL (prod):** `https://threatcrush.com`
- **Base URL (local):** `http://localhost:3000`
- **Content-Type:** `application/json` for every request body and response
  body unless noted.
- **Auth header (when required):** `Authorization: Bearer <supabase_access_token>`
  *(the same token returned by `POST /api/auth/login`)*.

---

## Quick reference

| Method   | Path                                  | Auth      | Purpose                                       |
| -------- | ------------------------------------- | --------- | --------------------------------------------- |
| `GET`    | `/api/modules`                        | none      | List / search / paginate published modules    |
| `POST`   | `/api/modules`                        | required  | Publish a new module                          |
| `GET`    | `/api/modules/{slug}`                 | none      | Module detail + versions + recent reviews     |
| `PATCH`  | `/api/modules/{slug}`                 | email     | Edit your module                              |
| `DELETE` | `/api/modules/{slug}?author_email=…`  | email     | Remove your module                            |
| `GET`    | `/api/modules/{slug}/install`         | none      | Read-only install info (does **not** count)   |
| `POST`   | `/api/modules/{slug}/install`         | none      | Install info **and** increment download count |
| `GET`    | `/api/modules/{slug}/review`          | none      | List reviews (paginated, 20 / page)           |
| `POST`   | `/api/modules/{slug}/review`          | email     | Create / update your review (one per email)   |
| `POST`   | `/api/modules/fetch-meta`             | none      | Probe a URL or GitHub repo for prefilled meta |

> **Auth modes.**
> - **none** — fully public.
> - **required** — must send a valid Supabase Bearer token *and* the
>   matching account must exist in `user_profiles` with `email_verified = true`.
> - **email** — author identity is asserted by `author_email` (in the body
>   or query string). The server confirms the email matches the row's
>   `author_email`. This is a soft check intended to be tightened to full
>   token auth later — treat it as advisory today.

---

## Authentication

### Get a token

```bash
curl -sS https://threatcrush.com/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"…"}'
```

The response includes `session.access_token`. Pass it as
`Authorization: Bearer <token>` on routes marked **required**.

### Token lifetime / refresh

Tokens are issued by Supabase auth. They expire on the schedule configured
for the project (typically 1 hour). Re-login to get a fresh one. There's no
ThreatCrush-specific refresh endpoint today.

### Why some endpoints check `author_email` instead

Update / delete / review routes were built early and key off `author_email`
in the request payload rather than the token. The server only verifies that
the email matches what's already on the row. This will be tightened to
full token-based ownership checks; see *Backwards-incompatible changes*
below.

---

## Errors

All errors are JSON in the shape:

```json
{ "error": "Human-readable reason" }
```

Common status codes:

| Status | When                                                           |
| ------ | -------------------------------------------------------------- |
| `400`  | Missing / malformed body or required field                     |
| `401`  | Not signed in, no token, or token doesn't resolve to a profile |
| `403`  | Email mismatch, unverified email, or wrong owner               |
| `404`  | Slug doesn't exist or `published = false`                      |
| `409`  | Slug already taken on `POST /api/modules`                      |
| `500`  | Database / unexpected upstream failure                         |
| `502`  | Upstream metadata fetch failed (`fetch-meta` only)             |

---

## Endpoints

### `GET /api/modules` — list / search

Returns published modules only.

**Query params**

| Param      | Default   | Notes                                                |
| ---------- | --------- | ---------------------------------------------------- |
| `search`   | *(none)*  | ILIKE match against `name`, `display_name`, `description`, `keywords` |
| `category` | *(any)*   | Exact match on `category`. Pass `all` to disable.    |
| `sort`     | `newest`  | `newest` \| `popular` \| `top-rated`                 |
| `page`     | `1`       | 1-indexed                                            |
| `limit`    | `20`      | Clamped to `[1, 50]`                                 |

**Response 200**

```json
{
  "modules": [ /* Module[] — see schema below */ ],
  "total": 137,
  "page": 1,
  "limit": 20,
  "totalPages": 7
}
```

**Example**

```bash
curl -sS "https://threatcrush.com/api/modules?search=ssh&sort=popular&limit=5"
```

---

### `POST /api/modules` — publish

Creates a new module listing. Slug is derived from `name` via `slugify` and
must be unique.

**Auth:** Bearer token required. The account must:

1. Exist in `user_profiles`,
2. Have `email_verified = true`,
3. Have `email` exactly equal to the `author_email` in the body.

**Request body**

| Field                     | Type       | Required | Notes                                              |
| ------------------------- | ---------- | -------- | -------------------------------------------------- |
| `name`                    | string     | yes      | Slugified into the URL — keep it stable and unique |
| `author_email`            | string     | yes      | Must match the logged-in account                   |
| `display_name`            | string     | no       | Defaults to `name`                                 |
| `description`             | string     | no       | Short tagline                                      |
| `long_description`        | string     | no       | Markdown OK                                        |
| `author_name`             | string     | no       |                                                    |
| `author_url`              | string     | no       |                                                    |
| `homepage_url`            | string     | no       |                                                    |
| `git_url`                 | string     | no       | If present, the first version will tag `v{version}` |
| `logo_url`                | string     | no       | Square preferred                                   |
| `banner_url`              | string     | no       | Wide hero image                                    |
| `screenshot_url`          | string     | no       |                                                    |
| `license`                 | string     | no       | SPDX identifier; defaults to `MIT`                 |
| `pricing_type`            | string     | no       | `free` \| `paid` \| `freemium` (defaults `free`)   |
| `price_usd`               | number     | no       | Required if `pricing_type` is `paid` / `freemium`  |
| `category`                | string     | no       | Defaults to `security`                             |
| `tags`                    | string[]   | no       |                                                    |
| `keywords`                | string     | no       | Comma-joined free-text used for search             |
| `version`                 | string     | no       | semver; defaults to `0.1.0`                        |
| `min_threatcrush_version` | string     | no       | semver range; defaults to `>=0.1.0`                |
| `os_support`              | string[]   | no       | Defaults to `["linux"]`                            |
| `capabilities`            | string[]   | no       |                                                    |

**Response 201**

```json
{ "module": { /* full Module row */ } }
```

A side effect: a row is also written to `module_versions` with
`version = body.version || "0.1.0"` and `git_tag = "v{version}"` if `git_url`
was provided.

**Errors**

- `400 name is required`
- `400 author_email is required`
- `401 You must create an account at threatcrush.com/auth/signup before publishing modules.`
- `403 Author email must match your logged-in account.`
- `403 Please verify your email before publishing modules.`
- `409 Module "{slug}" already exists`

**Example**

```bash
TOKEN="$(cat ~/.cache/threatcrush.token)"

curl -sS https://threatcrush.com/api/modules \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "URLhaus Feed",
    "author_email": "you@example.com",
    "description": "Polls URLhaus public feed and emits ThreatEvents",
    "git_url": "https://github.com/you/threatcrush-urlhaus-feed",
    "license": "MIT",
    "pricing_type": "free",
    "category": "threat-intel",
    "tags": ["feeds", "urlhaus", "abuse.ch"]
  }'
```

---

### `GET /api/modules/{slug}` — detail

Public. Fails with `404` if the slug doesn't exist or `published` is `false`.

**Response 200**

```json
{
  "module":   { /* Module */ },
  "versions": [ /* ModuleVersion[], newest first */ ],
  "reviews":  [ /* Review[], up to 20, newest first */ ]
}
```

For full pagination of reviews, use `GET /api/modules/{slug}/review`.

---

### `PATCH /api/modules/{slug}` — edit

Updates a subset of fields. Body **must** include `author_email`; the server
checks it against the row before applying.

**Whitelisted fields**

```
display_name, description, long_description, homepage_url, git_url,
logo_url, banner_url, screenshot_url, license, pricing_type, price_usd,
category, tags, keywords, version, min_threatcrush_version, os_support,
capabilities
```

Anything outside this list is silently ignored. The server also stamps
`updated_at = now()`.

**Response 200**

```json
{ "module": { /* updated row */ } }
```

**Errors**

- `400 Invalid JSON`
- `400 author_email is required`
- `403 Unauthorized` *(email mismatch)*
- `404 Module not found`

---

### `DELETE /api/modules/{slug}?author_email={email}` — remove

Deletes the module row. Cascade in the DB removes its versions, installs,
and reviews.

**Response 200**

```json
{ "deleted": true }
```

**Errors:** same authorisation pattern as `PATCH`.

---

### `GET /api/modules/{slug}/install` — read-only install info

Use this when a client wants to check what to install without affecting
analytics. It does **not** increment the download counter.

**Response 200**

```json
{
  "module": {
    "name": "URLhaus Feed",
    "slug": "urlhaus-feed",
    "version": "0.1.0",
    "downloads": 142,
    "license": "MIT",
    "min_threatcrush_version": ">=0.2.0",
    "os_support": ["linux", "darwin"],
    "install": {
      "npm_package": null,
      "git_url": "https://github.com/you/threatcrush-urlhaus-feed",
      "tarball_url": null
    }
  }
}
```

The CLI picks `install.npm_package` first if present, then `git_url`, then
`tarball_url`.

---

### `POST /api/modules/{slug}/install` — install + count

Same response shape as `GET /api/modules/{slug}/install`, **plus** it
increments `modules.downloads` and writes a row to `module_installs`.

**Request body** *(all optional)*

```json
{
  "user_email": "you@example.com",
  "version": "0.1.0",
  "platform": "linux-x64"
}
```

**Response 200**

```json
{
  "success": true,
  "downloads": 143,
  "module": { /* same shape as GET /install */ }
}
```

> **When to use which.** CLI / daemon: call **POST** so we get accurate
> install counts. UIs that just want to render the install snippet: call
> **GET**.

---

### `GET /api/modules/{slug}/review` — list reviews

**Query params**

| Param  | Default | Notes        |
| ------ | ------- | ------------ |
| `page` | `1`     | 1-indexed    |

Page size is fixed at **20**.

**Response 200**

```json
{
  "reviews": [ /* Review[] */ ],
  "total": 8,
  "page": 1
}
```

---

### `POST /api/modules/{slug}/review` — create / update review

Acts as **upsert** — one review per `(module_id, user_email)`. Submitting
again from the same email overwrites the prior review. After every write
the server recomputes `modules.rating_avg` and `modules.rating_count`.

**Request body**

| Field        | Type    | Required | Notes              |
| ------------ | ------- | -------- | ------------------ |
| `user_email` | string  | yes      | Must exist in `user_profiles` |
| `rating`     | integer | yes      | `1`–`5`            |
| `title`      | string  | no       |                    |
| `body`       | string  | no       | Markdown OK        |

**Response 201**

```json
{ "review": { /* Review row */ } }
```

**Errors**

- `400 user_email is required`
- `400 rating must be 1-5`
- `401 You must create an account to leave reviews.`
- `404 Module not found`

---

### `POST /api/modules/fetch-meta` — prefill helper

Used by the publish UI to fill the form from a website + GitHub repo. Public.
Best-effort; partial success is normal.

**Request body**

```json
{
  "url": "https://example.com/my-module",
  "git_url": "https://github.com/owner/repo"
}
```

At least one of `url` / `git_url` must be present.

**Response 200** *(merged; GitHub-preferred, web fills gaps)*

```json
{
  "name": "repo",
  "display_name": "repo",
  "description": "Short blurb",
  "long_description": "First 50KB of README.md",
  "logo_url": "https://…",
  "banner_url": "https://… (og:image)",
  "screenshot_url": "https://… (Microlink + Supabase storage)",
  "tags": ["topic1", "topic2"],
  "version": "0.1.0",
  "license": "MIT",
  "homepage_url": "https://…",
  "git_url": "https://github.com/owner/repo",
  "author_name": "owner",
  "stars": 17
}
```

**Behavior notes**

- GitHub fetch reads `repos/{owner}/{repo}`, then `README.md` (up to 50KB),
  then `package.json` for `version` and `keywords`, then `topics` for tags.
- Logo detection probes `/logo.svg`, `/logo.png`, `/favicon.{svg,png}` on
  the website origin, then `<link rel="icon">`, then `og:image`, then
  `/favicon.ico`.
- Screenshot uses **Microlink** and re-uploads the PNG to Supabase Storage
  bucket `module-screenshots`.
- All upstream calls are timeboxed (`AbortSignal.timeout`) — a single slow
  upstream won't hang the request.

**Errors**

- `400 url or git_url is required`
- `502 Failed to fetch metadata` *(generic — the response body's `error`
  field has the underlying cause when available)*

---

## Schemas

### Module *(row in `modules`)*

```ts
type Module = {
  id: string;                     // uuid
  name: string;                   // canonical name (UNIQUE)
  slug: string;                   // URL slug (UNIQUE)
  display_name: string;
  description: string | null;
  long_description: string | null;
  author_name: string | null;
  author_email: string | null;
  author_url: string | null;
  homepage_url: string | null;
  git_url: string | null;
  logo_url: string | null;
  banner_url: string | null;
  screenshot_url: string | null;
  license: string;                // SPDX id, default 'MIT'
  pricing_type: 'free' | 'paid' | 'freemium';   // default 'free'
  price_usd: number | null;
  category: string;               // default 'security'
  tags: string[];                 // default []
  keywords: string | null;        // free-text used by ILIKE search
  version: string;                // semver, default '0.1.0'
  min_threatcrush_version: string;// default '>=0.1.0'
  os_support: string[];           // default ['linux']
  capabilities: string[];         // default []
  npm_package: string | null;
  tarball_url: string | null;
  downloads: number;              // default 0
  rating_avg: number;             // default 0  (numeric(3,2))
  rating_count: number;           // default 0
  verified: boolean;              // default false (admin-only)
  published: boolean;             // default true
  featured: boolean;              // default false (admin-only)
  created_at: string;             // ISO timestamp
  updated_at: string;             // ISO timestamp
};
```

> Some columns aren't currently writable from the public publish API:
> `npm_package`, `tarball_url`, `verified`, `featured`. These are managed
> internally and returned read-only.

### ModuleVersion *(row in `module_versions`)*

```ts
type ModuleVersion = {
  id: string;
  module_id: string;
  version: string;                // semver
  changelog: string | null;
  package_url: string | null;
  git_tag: string | null;
  min_threatcrush_version: string | null;
  created_at: string;
};
```

There is no public `POST /api/modules/{slug}/versions` yet — bumping the
top-level `version` via `PATCH` is how authors signal a new release today.
A dedicated versions endpoint is on the roadmap.

### Review *(row in `module_reviews`)*

```ts
type Review = {
  id: string;
  module_id: string;
  user_email: string;
  rating: 1 | 2 | 3 | 4 | 5;
  title: string | null;
  body: string | null;
  created_at: string;
};
```

Uniqueness is enforced on `(module_id, user_email)`.

### Install *(row in `module_installs`)*

```ts
type Install = {
  id: string;
  module_id: string;
  user_email: string | null;
  version: string | null;
  platform: string | null;        // e.g. "linux-x64", "darwin-arm64"
  created_at: string;
};
```

---

## Module manifest (`mod.toml`)

The publish API only writes DB metadata. The **runtime** contract for an
installable module is the `mod.toml` shipped in the module's repository.
Fields here mirror the columns above so the Web publish UI and the CLI
agree.

```toml
[module]
name = "urlhaus-feed"
version = "0.1.0"
description = "Polls URLhaus public feed and emits ThreatEvents"
author = "Your Name"
license = "MIT"                   # SPDX id
homepage = "https://example.com/modules/urlhaus-feed"

[module.pricing]
type = "free"                     # free | paid | freemium
# price_usd = 49.0                # required if type = paid | freemium
# billing = "monthly"             # one_time | monthly | usage

[module.requirements]
threatcrush = ">=0.2.0"           # semver range
os = ["linux", "darwin"]
capabilities = ["network:outbound"]

[module.config.defaults]
enabled = true
poll_interval_seconds = 300
# any module-specific defaults here — these become ctx.config[...] at runtime
```

The full TS interface a runtime module implements (`ThreatCrushModule`,
`ModuleContext`, `ThreatEvent`, `Alert`) is exported from
[`@threatcrush/sdk`](../apps/sdk/src/index.ts).

Reference boilerplates:

- [`boilerplates/module-example/`](../boilerplates/module-example/) — minimal
  hello-world module that subscribes to events.
- [`boilerplates/free-module/`](../boilerplates/free-module/) — MIT-licensed
  fetch-loop API integration template.
- [`boilerplates/paid-module/`](../boilerplates/paid-module/) — paid template
  with `login` / `logout` / `status` CLI commands and a license-gated init.

---

## Worked examples

### Publish a module from the shell

```bash
# 1. authenticate
TOKEN="$(curl -sS https://threatcrush.com/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"…"}' \
  | jq -r '.session.access_token')"

# 2. prefill from your repo
curl -sS https://threatcrush.com/api/modules/fetch-meta \
  -H 'Content-Type: application/json' \
  -d '{"git_url":"https://github.com/you/threatcrush-urlhaus-feed"}' > meta.json

# 3. publish
curl -sS https://threatcrush.com/api/modules \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$(jq '. + {author_email:"you@example.com",pricing_type:"free"}' meta.json)"
```

### Update the version after a release

```bash
curl -sS -X PATCH https://threatcrush.com/api/modules/urlhaus-feed \
  -H 'Content-Type: application/json' \
  -d '{
    "author_email": "you@example.com",
    "version": "0.2.0",
    "min_threatcrush_version": ">=0.2.0"
  }'
```

### Increment install count from a CLI installer

```bash
curl -sS -X POST https://threatcrush.com/api/modules/urlhaus-feed/install \
  -H 'Content-Type: application/json' \
  -d '{
    "user_email": "ops@your-org.com",
    "version": "0.2.0",
    "platform": "linux-x64"
  }'
```

### Leave a 5-star review

```bash
curl -sS -X POST https://threatcrush.com/api/modules/urlhaus-feed/review \
  -H 'Content-Type: application/json' \
  -d '{
    "user_email": "happy@example.com",
    "rating": 5,
    "title": "Caught two C2 domains in week one",
    "body": "Drop-in install, clean event shape."
  }'
```

---

## Rate limits

There are **no enforced rate limits** on these endpoints today. Don't abuse
them — `fetch-meta` in particular makes outbound calls. Expect token-bucket
limits to land before public launch.

---

## Backwards-incompatible changes on the roadmap

The following are known sharp edges that **will** change. Build flexibility
into your client.

1. **`PATCH` / `DELETE` / `review` will require Bearer auth.** Today they
   accept `author_email` as a soft proof of ownership. Future versions will
   require the same `Authorization: Bearer …` header as `POST /api/modules`,
   and `author_email` will become advisory-only.
2. **A `POST /api/modules/{slug}/versions` endpoint** will land for
   first-class version management (changelog, tarball uploads, signed
   releases). Today, version bumps go through `PATCH /api/modules/{slug}`.
3. **Module signing.** Verified publishers will be able to sign release
   tarballs; the install API will return `signature_url` + `pubkey` so the
   CLI can verify before running.
4. **`pricing_type = "paid"` will require Stripe / CoinPay metadata.**
   Currently the price is stored but no checkout flow is wired into the
   install path. This will change once the paid-module experience ships.

---

## Source of truth

- **Route handlers:** `apps/web/src/app/api/modules/`
- **DB schema:** `supabase/migrations/20260404140000_modules_marketplace.sql`
- **SDK / runtime contract:** `apps/sdk/src/index.ts`
- **Boilerplates:** `boilerplates/{module-example,free-module,paid-module}/`
- **Web docs page:** `apps/web/src/app/docs/modules/page.tsx`

If anything in this doc drifts from the source, **the source wins**. Open
an issue at <https://github.com/profullstack/threatcrush/issues>.
