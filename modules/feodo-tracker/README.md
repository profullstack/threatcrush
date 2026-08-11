# Feodo Tracker

A defensive ThreatCrush module that polls the public
[abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) botnet C2 blocklist and
emits structured `ThreatEvent` records for newly observed command-and-control
servers.

## Features

- Uses the official Feodo Tracker CSV feed; no API key is required.
- Emits active C2 indicators by default and can optionally include offline ones.
- Persists indicator keys to avoid repeating events after a restart.
- Validates IP addresses and ports before emitting an event.
- Requires HTTPS for custom feed URLs and limits events per poll.
- Includes parser and event-mapping tests.

This module consumes threat intelligence only. It does not scan, contact, or
attempt to exploit any listed server.

## Install

```bash
threatcrush modules install feodo-tracker
```

For local development in the ThreatCrush monorepo:

```bash
pnpm install
pnpm --filter threatcrush-module-feodo-tracker build
pnpm --filter threatcrush-module-feodo-tracker test
```

## Configuration

Copy `config/example.conf.toml` into the ThreatCrush module configuration and
adjust these values if needed:

| Setting | Default | Description |
| --- | --- | --- |
| `poll_interval_seconds` | `900` | Poll interval, with a runtime minimum of 60 seconds. |
| `feed_url` | Official Feodo CSV URL | HTTPS feed endpoint. |
| `emit_offline` | `false` | Emit inactive historical C2 entries too. |
| `max_events_per_poll` | `100` | Maximum new events emitted in one poll. |

## Event shape

Active C2 servers produce a high-severity network event:

```json
{
  "module": "feodo-tracker",
  "category": "network",
  "severity": "high",
  "message": "Feodo Tracker: QakBot C2 203.0.113.8:443 is online",
  "source_ip": "203.0.113.8",
  "details": {
    "destination_ip": "203.0.113.8",
    "destination_port": 443,
    "c2_status": "online",
    "malware": "QakBot"
  }
}
```

## Data source and license

The module code is MIT licensed. Feodo Tracker data remains subject to the
[abuse.ch terms of use](https://feodotracker.abuse.ch/blocklist/).
