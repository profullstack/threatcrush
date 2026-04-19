# @threatcrush/sdk

TypeScript types + helpers for building ThreatCrush modules.

**Status:** alpha. Not yet published to npm — the marketplace install flow that would consume it is still v0.2 work.

## Install (once published)

```bash
npm i @threatcrush/sdk    # as a dev-only type dep
```

## Writing a module

```ts
import type {
  ThreatCrushModule,
  ModuleContext,
  ThreatEvent,
} from "@threatcrush/sdk";

export default class SSHGuard implements ThreatCrushModule {
  name = "ssh-guard";
  version = "0.1.0";

  async init(ctx: ModuleContext) {
    ctx.subscribe("log:auth", (event) => this.onAuth(event));
  }

  async start() { /* begin monitoring */ }

  async stop() { /* clean up */ }

  async onEvent(event: ThreatEvent) {
    if (event.severity === "high") {
      ctx.alert({ title: "SSH brute force", severity: "high", event });
    }
  }
}
```

Pair with a `mod.toml`:

```toml
[module]
name = "ssh-guard"
version = "0.1.0"
description = "Monitor and protect SSH connections"
author = "You"
license = "MIT"
```

Install it locally:

```bash
threatcrush modules install ./my-module
threatcrush stop && threatcrush start   # reload the daemon
```

## What's exported

- `ThreatCrushModule`, `ModuleContext`, `ModuleConfig`, `ModuleLogger`, `ModuleManifest`
- `ThreatEvent`, `EventSeverity`, `EventCategory`, `Alert`, `EventPayload` (alias)
- `normalizePhone(raw)`, `severityAnsi(severity)` — tiny helpers

See `src/index.ts` for the full surface.

## Dev

```bash
pnpm --filter @threatcrush/sdk build   # tsc → dist/
```
