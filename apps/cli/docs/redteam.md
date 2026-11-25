# Redteam — autonomous security pass

`threatcrush redteam <url>` runs an autonomous recon → prioritise → probe →
verify → report loop against a target **you own or are authorized to test**. It
covers the same ground as the ARTEX-class agentic pentest tools, but is built to
be *simpler to use*: one target, nothing to stand up, deterministic by default,
and benign throughout.

## Authorized use

Redteam maps and probes a live target. Run it **only** against systems you own
or have explicit written permission to test — unauthorized scanning may be
illegal. The command refuses to start until you confirm authorization (an
interactive prompt, or `--authorized`).

## What it does

1. **Recon** — fetches the target and builds an attack-surface map: same-origin
   links, forms, `robots.txt` and `sitemap.xml` paths, and any OpenAPI/Swagger
   spec the app exposes (parsed into concrete routes). All read-only GETs.
2. **Plan** — ranks the routes by risk (auth/admin/API paths, write methods,
   user-input forms). Deterministic; no model required. `--ai` optionally lets a
   **c0mpute** model re-rank the queue (never a paid provider; falls back to the
   deterministic order on any error).
3. **Probe** — for each route within the budget, runs benign checks:
   unauthenticated reach of sensitive endpoints, unencoded input reflection
   (reflected-XSS signal, via a harmless canary), error/stack disclosure,
   directory listing, wide-open CORS, and version banners.
4. **Report** — rolls findings into the standard ThreatCrush run result.

## Safety guarantees

- Only **GET / HEAD / OPTIONS** are ever sent. Write methods found in the
  surface map are downgraded to an `OPTIONS` pre-flight — never executed.
- Injection checks use a harmless per-run canary and look only for **unencoded
  reflection**; nothing is executed on the target.
- Transport errors self-correct (one retry); a suspected unauthenticated-access
  finding is **verified** with a second request before it is kept.

## Usage

```sh
threatcrush redteam https://app.example.com            # prompts for authorization
threatcrush redteam https://app.example.com --authorized
threatcrush redteam https://app.example.com --max 50 --timeout 10000
threatcrush redteam https://app.example.com --html-only   # landing page only
threatcrush redteam https://app.example.com --ai          # c0mpute re-ranking (TC_COMPUTE_URL)
threatcrush redteam https://app.example.com --json
```

Env for `--ai`: `TC_COMPUTE_URL` (c0mpute gateway base), optional
`TC_COMPUTE_MODEL`, `TC_COMPUTE_KEY`.
