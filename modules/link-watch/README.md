# Link Watch

A paid ThreatCrush module that crawls the sites you list and reports every
broken link and asset on them: 404s and other 4xx, 5xx, and hosts that no
longer resolve. Each break is one `web` event, emitted once when it first
appears, with the pages that link to it, so it reaches your alert rules like
any other detection.

- **Your own pages** are walked from the site root and `/sitemap.xml`, up to
  `max_pages`; every `<a>`, `<link>`, `<img>`, `<script>`, `<iframe>` and
  media URL on them is checked once.
- **Severity:** a broken URL on your own site is `medium` (`high` when it is a
  5xx or the site is unreachable); a broken external link is `low`.
- **Images on other sites** are skipped unless `check_external_media = true`: on sites showing publishers' or users' content they are other people's files.
- **Not reported:** 401, 402, 403, 405, 429 and 999 (bot walls and paywalls, not breakage), and
  third-party URLs that only time out.

## Pricing

Link Watch needs an active subscription for your ThreatCrush organization,
paid in crypto through CoinPay: see https://threatcrush.com/link-watch. Each
run checks `GET /api/v1/entitlements/link-watch` with `api_key` (a
`tc_agent_` key) or the session `threatcrush login` saved; without one it
does nothing and raises one `info` alert.

## Configure

```toml
# /etc/threatcrush/threatcrushd.conf.d/link-watch.conf
[modules.link-watch]
sites = ["https://example.com"]
interval_hours = 24
ignore_paths = ["/api/"]
```

See `config/example.conf.toml` for every option.
