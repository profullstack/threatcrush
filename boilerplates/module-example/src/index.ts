// Example ThreatCrush module
// This follows the interface described in PRD.md until @threatcrush/sdk is published.

export interface EventPayload {
  type: string;
  data?: Record<string, unknown>;
  timestamp?: string;
}

export interface ModuleContext {
  config: Record<string, unknown>;
  logger: {
    info: (...args: unknown[]) => void;
    warn: (...args: unknown[]) => void;
    error: (...args: unknown[]) => void;
  };
  alert?: (payload: {
    title: string;
    severity?: "low" | "medium" | "high" | "critical";
    body?: string;
    event?: EventPayload;
  }) => Promise<void> | void;
  subscribe?: (topic: string) => void;
}

export default class ExampleAlertModule {
  name = "example-alert-module";
  version = "0.1.0";
  private ctx!: ModuleContext;

  async init(ctx: ModuleContext): Promise<void> {
    this.ctx = ctx;
    this.ctx.logger.info(`[${this.name}] init`);
  }

  async start(): Promise<void> {
    this.ctx.logger.info(`[${this.name}] start`);

    const watchEventTypes = (this.ctx.config.watch_event_types as string[] | undefined) ?? [];
    for (const topic of watchEventTypes) {
      this.ctx.subscribe?.(topic);
    }
  }

  async onEvent(event: EventPayload): Promise<void> {
    this.ctx.logger.info(`[${this.name}] event`, event.type);

    if (event.type === "log:auth") {
      await this.ctx.alert?.({
        title: "Example module noticed an auth-related event",
        severity: "medium",
        body: "Replace this with real detection logic.",
        event,
      });
    }
  }

  async stop(): Promise<void> {
    this.ctx.logger.info(`[${this.name}] stop`);
  }
}
