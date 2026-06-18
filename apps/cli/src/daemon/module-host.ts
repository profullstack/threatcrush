import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import TOML from '@iarna/toml';
import type { EventBus } from './event-bus.js';
import { PATHS } from './paths.js';
import { LogWatcher } from './watchers/log-watcher.js';
import { JournalWatcher } from './watchers/journal-watcher.js';
import { NetworkMonitor } from '../modules/network-monitor/index.js';
import { DnsMonitor } from '../modules/dns-monitor/index.js';
import { loadModuleConfigs } from '../core/config.js';
import { getModuleState, setModuleState } from '../core/state.js';
import type { ModuleConfig, ModuleManifest } from '../types/config.js';
import type { ThreatEvent } from '../types/events.js';
import type { ModuleAlert, ThreatCrushModule } from '../types/module.js';

interface HostedModule {
  name: string;
  version: string;
  source: 'builtin' | 'installed';
  status: 'running' | 'loaded' | 'error' | 'disabled';
  events: number;
  detail?: string;
  path?: string;
  config?: ModuleConfig;
  instance?: ThreatCrushModule;
}

export class ModuleHost {
  private modules = new Map<string, HostedModule>();
  private logWatcher: LogWatcher | null = null;
  private journalWatcher: JournalWatcher | null = null;
  private networkMonitor: NetworkMonitor | null = null;
  private dnsMonitor: DnsMonitor | null = null;

  constructor(private bus: EventBus) {
    bus.on('event', (event) => {
      const mod = this.modules.get(event.module);
      if (mod) mod.events++;
      for (const hosted of this.modules.values()) {
        if (hosted.status !== 'running' || !hosted.instance?.onEvent) continue;
        void hosted.instance.onEvent(event).catch((err) => {
          hosted.status = 'error';
          hosted.detail = `onEvent failed: ${String((err as Error).message || err)}`;
          this.bus.announceModule(hosted.name, 'error', hosted.detail);
        });
      }
    });
  }

  async start(): Promise<void> {
    this.registerBuiltins();
    await this.discoverAndStartInstalled();

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

    this.journalWatcher = new JournalWatcher(this.bus);
    if (this.journalWatcher.start()) {
      const mod = this.modules.get('user-journal');
      if (mod) {
        mod.status = 'running';
        mod.detail = `tailing ${JournalWatcher.scopeArgs().includes('--user') ? 'user journal' : 'system journal'}`;
        this.bus.announceModule('user-journal', 'running', mod.detail);
      }
    }

    // Network monitor (PRD 04)
    this.networkMonitor = new NetworkMonitor(this.bus);
    if (this.networkMonitor.start()) {
      const nmod = this.modules.get('network-monitor');
      if (nmod) {
        nmod.status = 'running';
        nmod.detail = 'monitoring connections via conntrack/ss';
        this.bus.announceModule('network-monitor', 'running', nmod.detail);
      }
    }

    // DNS monitor (PRD 05)
    this.dnsMonitor = new DnsMonitor(this.bus);
    if (this.dnsMonitor.start()) {
      const dmod = this.modules.get('dns-monitor');
      if (dmod) {
        dmod.status = 'running';
        dmod.detail = 'monitoring DNS queries';
        this.bus.announceModule('dns-monitor', 'running', dmod.detail);
      }
    }
  }

  async stop(): Promise<void> {
    this.logWatcher?.stop();
    this.journalWatcher?.stop();
    this.networkMonitor?.stop();
    this.dnsMonitor?.stop();
    for (const mod of this.modules.values()) {
      try {
        if (mod.instance && mod.status === 'running') {
          await mod.instance.stop();
        }
      } catch (err) {
        mod.status = 'error';
        mod.detail = `stop failed: ${String((err as Error).message || err)}`;
        this.bus.announceModule(mod.name, 'error', mod.detail);
        continue;
      }
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
      { name: 'user-journal', version: '0.1.0', source: 'builtin', status: 'loaded', events: 0 },
      { name: 'network-monitor', version: '0.1.0', source: 'builtin', status: 'loaded', events: 0 },
      { name: 'dns-monitor', version: '0.1.0', source: 'builtin', status: 'loaded', events: 0 },
    ];
    for (const m of builtins) this.modules.set(m.name, m);
  }

  private async discoverAndStartInstalled(): Promise<void> {
    if (!existsSync(PATHS.moduleDir)) return;
    const configs = loadModuleConfigs(PATHS.confD);
    const entries = readdirSync(PATHS.moduleDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const manifestPath = join(PATHS.moduleDir, entry.name, 'mod.toml');
      if (!existsSync(manifestPath)) continue;
      try {
        const manifest = TOML.parse(readFileSync(manifestPath, 'utf-8')) as unknown as ModuleManifest;
        const name = manifest.module?.name || entry.name;
        const defaults = manifest.module?.config?.defaults || {};
        const config = {
          enabled: true,
          ...defaults,
          ...(configs.get(name) || {}),
        } as ModuleConfig;
        const hosted: HostedModule = {
          name,
          version: manifest.module?.version || '0.0.0',
          source: 'installed',
          status: config.enabled === false ? 'disabled' : 'loaded',
          events: 0,
          path: join(PATHS.moduleDir, entry.name),
          config,
        };
        this.modules.set(name, hosted);
        if (config.enabled === false) continue;
        await this.startInstalled(hosted);
      } catch (err) {
        const name = entry.name;
        this.modules.set(name, {
          name,
          version: '0.0.0',
          source: 'installed',
          status: 'error',
          events: 0,
          detail: `manifest load failed: ${String((err as Error).message || err)}`,
          path: join(PATHS.moduleDir, entry.name),
        });
      }
    }
  }

  private async startInstalled(hosted: HostedModule): Promise<void> {
    const entrypoint = this.installedEntrypoint(hosted.path!);
    if (!entrypoint) {
      hosted.status = 'loaded';
      hosted.detail = 'no built entrypoint found; run npm install && npm run build in the module directory';
      return;
    }

    try {
      const imported = await import(pathToFileURL(entrypoint).href);
      const exported = imported.default || imported.module || imported;
      const instance = typeof exported === 'function' ? new exported() : exported;
      if (!this.isThreatCrushModule(instance)) {
        throw new Error('entrypoint does not export a ThreatCrush module');
      }

      hosted.instance = instance;
      await instance.init(this.contextFor(hosted));
      await instance.start();
      hosted.status = 'running';
      hosted.detail = `started from ${entrypoint}`;
      this.bus.announceModule(hosted.name, 'running', hosted.detail);
    } catch (err) {
      hosted.status = 'error';
      hosted.detail = String((err as Error).message || err);
      this.bus.announceModule(hosted.name, 'error', hosted.detail);
    }
  }

  private installedEntrypoint(modulePath: string): string | null {
    const packageJson = join(modulePath, 'package.json');
    const candidates: string[] = [];
    if (existsSync(packageJson)) {
      try {
        const pkg = JSON.parse(readFileSync(packageJson, 'utf-8')) as { main?: string };
        if (pkg.main) candidates.push(join(modulePath, pkg.main));
      } catch {
        // fall through to conventional paths
      }
    }
    candidates.push(join(modulePath, 'dist', 'index.js'), join(modulePath, 'index.js'));
    return candidates.find((candidate) => existsSync(candidate)) || null;
  }

  private isThreatCrushModule(value: unknown): value is ThreatCrushModule {
    return Boolean(
      value &&
      typeof value === 'object' &&
      typeof (value as ThreatCrushModule).init === 'function' &&
      typeof (value as ThreatCrushModule).start === 'function' &&
      typeof (value as ThreatCrushModule).stop === 'function',
    );
  }

  private contextFor(hosted: HostedModule) {
    return {
      config: hosted.config || { enabled: true },
      logger: this.loggerFor(hosted.name),
      emit: (event: ThreatEvent) => this.bus.publish(event),
      subscribe: (eventType: string, handler: (event: ThreatEvent) => void) => {
        this.bus.on('event', (event) => {
          if (event.category === eventType || event.module === eventType) handler(event);
        });
      },
      alert: (alert: ModuleAlert) => {
        this.bus.emit('alert', alert.event || {
          timestamp: new Date(),
          module: hosted.name,
          category: 'system',
          severity: alert.severity,
          message: alert.title,
          details: alert.body ? { body: alert.body } : undefined,
        });
      },
      getState: (key: string) => getModuleState(hosted.name, key),
      setState: (key: string, value: unknown) => setModuleState(hosted.name, key, value),
    };
  }

  private loggerFor(moduleName: string) {
    return {
      debug: (msg: string, ...args: unknown[]) => console.debug(`[${moduleName}] ${msg}`, ...args),
      info: (msg: string, ...args: unknown[]) => console.info(`[${moduleName}] ${msg}`, ...args),
      warn: (msg: string, ...args: unknown[]) => console.warn(`[${moduleName}] ${msg}`, ...args),
      error: (msg: string, ...args: unknown[]) => console.error(`[${moduleName}] ${msg}`, ...args),
    };
  }
}
