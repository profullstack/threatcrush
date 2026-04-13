/**
 * Example ThreatCrush Module
 *
 * Demonstrates the interface for building ThreatCrush security modules.
 * Once @threatcrush/sdk is published, replace these local types with:
 *   import type { ThreatCrushModule, ModuleContext, ThreatEvent, Alert } from '@threatcrush/sdk';
 */

import type { ThreatEvent, EventCategory, EventSeverity, ModuleContext, Alert, ThreatCrushModule } from '../../sdk/src/index.js';

export default class ExampleAlertModule implements ThreatCrushModule {
  name = 'example-alert-module';
  version = '0.1.0';
  description = 'Sends an alert whenever an auth event is detected';

  private ctx!: ModuleContext;

  async init(ctx: ModuleContext): Promise<void> {
    this.ctx = ctx;
    this.ctx.logger.info('[%s] initialized', this.name);
  }

  async start(): Promise<void> {
    this.ctx.logger.info('[%s] started', this.name);

    const watchEventTypes = (this.ctx.config.watch_event_types as string[] | undefined) ?? [
      'log:auth',
    ];
    for (const topic of watchEventTypes) {
      this.ctx.subscribe(topic, (event: ThreatEvent) => {
        void this.onEvent(event);
      });
    }
  }

  async onEvent(event: ThreatEvent): Promise<void> {
    if (event.category === 'auth' || event.module === 'ssh-guard') {
      const alert: Alert = {
        title: 'Auth event detected',
        severity: event.severity === 'high' || event.severity === 'critical' ? event.severity : 'medium',
        body: `Module received auth event: ${event.message}`,
        event,
      };
      this.ctx.alert(alert);
    }
  }

  async stop(): Promise<void> {
    this.ctx.logger.info('[%s] stopped', this.name);
  }
}
