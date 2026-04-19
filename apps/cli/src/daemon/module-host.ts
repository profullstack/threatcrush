import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import TOML from '@iarna/toml';
import type { EventBus } from './event-bus.js';
import { PATHS } from './paths.js';
import { LogWatcher } from './watchers/log-watcher.js';
import type { ModuleManifest } from '../types/config.js';

interface HostedModule {
  name: string;
  version: string;
  source: 'builtin' | 'installed';
  status: 'running' | 'loaded' | 'error' | 'disabled';
  events: number;
  detail?: string;
}

export class ModuleHost {
  private modules = new Map<string, HostedModule>();
  private logWatcher: LogWatcher | null = null;

  constructor(private bus: EventBus) {
    bus.on('event', (event) => {
      const mod = this.modules.get(event.module);
      if (mod) mod.events++;
    });
  }

  async start(): Promise<void> {
    this.registerBuiltins();
    this.discoverInstalled();

    this.logWatcher = new LogWatcher(this.bus);
    const watched = this.logWatcher.start();

    for (const modName of this.logWatcher.activeModules()) {
      const mod = this.modules.get(modName);
      if (mod) {
        mod.status = 'running';
        mod.detail = `watching ${watched.length} log source(s)`;
        this.bus.announceModule(modName, 'running', mod.detail);
      }
    }
  }

  async stop(): Promise<void> {
    this.logWatcher?.stop();
    for (const mod of this.modules.values()) {
      mod.status = 'loaded';
      this.bus.announceModule(mod.name, 'stopped');
    }
  }

  summary(): Array<{ name: string; status: string; events: number; detail?: string }> {
    return [...this.modules.values()].map((m) => ({
      name: m.name,
      status: m.status,
      events: m.events,
      detail: m.detail,
    }));
  }

  private registerBuiltins(): void {
    const builtins: HostedModule[] = [
      { name: 'log-watcher', version: '0.1.0', source: 'builtin', status: 'loaded', events: 0 },
      { name: 'ssh-guard', version: '0.1.0', source: 'builtin', status: 'loaded', events: 0 },
    ];
    for (const m of builtins) this.modules.set(m.name, m);
  }

  private discoverInstalled(): void {
    if (!existsSync(PATHS.moduleDir)) return;
    const entries = readdirSync(PATHS.moduleDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const manifestPath = join(PATHS.moduleDir, entry.name, 'mod.toml');
      if (!existsSync(manifestPath)) continue;
      try {
        const manifest = TOML.parse(readFileSync(manifestPath, 'utf-8')) as unknown as ModuleManifest;
        const name = manifest.module?.name || entry.name;
        this.modules.set(name, {
          name,
          version: manifest.module?.version || '0.0.0',
          source: 'installed',
          status: 'loaded',
          events: 0,
        });
      } catch {
        // skip malformed
      }
    }
  }
}
