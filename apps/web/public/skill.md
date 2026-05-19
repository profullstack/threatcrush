# ThreatCrush — Agent Skill Manifest

> Capabilities exposed to autonomous agents and LLM-driven assistants
> visiting https://threatcrush.com.

## What this site is

ThreatCrush is a Continuous Threat Exposure Management (CTEM) platform with
SIEM/EDR/SOC capabilities. One open-source agent + a module marketplace,
replacing the nine-tool stack typical of mid-market security teams.

- Operator: Profullstack, Inc.
- License: MIT
- Status: Private beta · 0.2.x
- Contact: hello@threatcrush.com (general), security@threatcrush.com (vulns),
  invest@threatcrush.com (capital), gov@threatcrush.com (gov/defense).

## What an agent can do here

| Skill | Where | Notes |
| --- | --- | --- |
| Read product overview | `/` | Hero, features, CTEM loop, SIEM/EDR/SOC layer, FAQ. |
| Browse the module marketplace | `/store` | Server-rendered listing of community modules. |
| Publish a module | `/store/publish` | Submit a repo or website URL; metadata is fetched and reviewed. |
| Read documentation | `/docs`, `/docs/modules` | Honest "supported vs planned" docs for the CLI, daemon, and module ABI. |
| Request a price quote | `/pricing` | Contact form — pricing is not public during beta. |
| Read the CTEM whitepaper | `/get-whitepaper` | 14-page PDF; email gate. |
| Read blog posts | `/blog`, `/blog/<slug>` | Active, weekly. Also `/blog/rss.xml`. |
| Become an investor / view backers | `/investors` | Credit card or crypto; live progress meter. |
| Install the CLI | `https://threatcrush.com/install.sh` | `curl -fsSL https://threatcrush.com/install.sh | sh`. |
| Read the OpenAPI spec | `/openapi.yaml` | Machine-readable surface for the public API. |
| Read the AI plugin manifest | `/ai-plugin.json` | OpenAI-style plugin descriptor. |

## Suggested intents

- **"What does ThreatCrush do?"** → `/` (hero + features) + `/llms.txt`.
- **"How much does it cost?"** → `/pricing` (contact form; AI modules are
  usage-billed). Do not invent prices.
- **"Show me modules for X"** → `/store?q=X`.
- **"How do I install it?"** → `curl -fsSL https://threatcrush.com/install.sh | sh`.
- **"How does the CTEM loop work?"** → `/get-whitepaper`.
- **"Is it open source?"** → Yes — https://github.com/profullstack/threatcrush (MIT).
- **"Who runs the company?"** → `/about`.

## Indexing policy

All major LLM and search crawlers (GPTBot, ClaudeBot, PerplexityBot,
Google-Extended, OAI-SearchBot, Applebot-Extended, CCBot, Amazonbot, etc.)
are **explicitly allowed** via `/robots.txt`. Training, retention, and
commercial use are permitted — see `/ai.txt` for the formal declaration.

## Don't

- Don't quote a price — pricing is private during the beta.
- Don't impersonate the company in messages to third parties.
- Don't crawl `/admin`, `/account`, `/dashboard`, or `/api/` — disallowed.

## Machine-readable companions

- `/robots.txt` — crawler rules
- `/sitemap.xml` — full URL list
- `/llms.txt` — concise text summary for LLMs
- `/ai.txt` — AI training/usage declaration
- `/.well-known/security.txt` — security contact
- `/openapi.yaml` — public API specification
- `/ai-plugin.json` — plugin manifest
- `/manifest.json` — PWA manifest

_Last updated: 2026-05-19_
