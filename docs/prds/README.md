# ThreatCrush PRDs — Launch-Readiness Backlog

These PRDs stub out **every feature that still needs to be built** for the two
launch surfaces:

- **Web / PWA** (`apps/web/`)
- **CLI / SDK** (`apps/cli/`, `apps/sdk/`)

Desktop, mobile, browser extension, and hardware are **out of scope** here — see
`docs/SURFACES.md` and `docs/FUTURE_PLANS.md` for those.

Each PRD is grounded in the gap between the master `docs/PRD.md` vision and what
is actually implemented today (as of CLI/web `v0.2.1`). The master PRD describes a
detections + remediation + hardening platform; the shipped product is currently
oriented around `servers` + `properties` (pentest/scan targets) and is missing
most of the detection/remediation/hardening backbone.

## Priority key

| Priority | Meaning |
|---|---|
| **P0** | Launch-blocker. Product is incomplete / misleading without it. |
| **P1** | Strongly wanted at launch; can slip to a fast-follow point release. |
| **P2** | Post-launch / v0.2+. Stubbed here so the scope is captured. |

## Index

### Foundation
| # | PRD | Surface | Priority |
|---|---|---|---|
| 00 | [Detection data model & event ingest](./00-detection-data-model.md) | API/DB | **P0** |

### CLI / Daemon
| # | PRD | Surface | Priority |
|---|---|---|---|
| 01 | [Detection rule engine & rule packs](./01-detection-rule-engine.md) | CLI | **P0** |
| 02 | [Firewall auto-remediation](./02-firewall-auto-remediation.md) | CLI | **P0** |
| 03 | [Hardening scanner](./03-hardening-scanner.md) | CLI | **P0** |
| 04 | [Network monitor module](./04-network-monitor-module.md) | CLI | P1 |
| 05 | [DNS monitor module](./05-dns-monitor-module.md) | CLI | P1 |
| 06 | [Code scanner engine](./06-code-scanner-engine.md) | CLI | P1 |
| 07 | [Pentest engine](./07-pentest-engine.md) | CLI | P1 |
| 08 | [Alerting channels & alert rules](./08-alerting-and-alert-rules.md) | CLI/Web | **P0** |

### SDK
| # | PRD | Surface | Priority |
|---|---|---|---|
| 09 | [Module SDK & npm publish](./09-module-sdk-and-publish.md) | SDK | P1 |

### Web / PWA
| # | PRD | Surface | Priority |
|---|---|---|---|
| 10 | [Dashboard detections feed](./10-dashboard-detections-feed.md) | Web/PWA | **P0** |
| 11 | [Dashboard hardening findings](./11-dashboard-hardening-findings.md) | Web/PWA | **P0** |
| 12 | [Remediation & blocklist UI](./12-remediation-and-blocklist-ui.md) | Web/PWA | **P0** |
| 13 | [Alert settings UI](./13-alert-settings-ui.md) | Web/PWA | P1 |
| 14 | [PWA offline & push](./14-pwa-offline-and-push.md) | PWA | P1 |

### Ops / Distribution
| # | PRD | Surface | Priority |
|---|---|---|---|
| 15 | [Self-hosting package](./15-self-hosting-package.md) | Web/Ops | P1 |
| 16 | [Module marketplace](./16-module-marketplace.md) | Web | P2 |

## Template

Every PRD follows the skeleton in [`_TEMPLATE.md`](./_TEMPLATE.md). Copy it for new
features.
