import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import TOML from '@iarna/toml';
import type { LoadedModule } from '../types/module.js';
import type { ModuleManifest } from '../types/config.js';
import { loadModuleConfigs } from './config.js';
import { PATHS } from '../daemon/paths.js';

export function discoverModules(
  moduleDir?: string,
  confDir?: string,
): LoadedModule[] {
  const modules: LoadedModule[] = [];
  const configs = loadModuleConfigs(confDir || PATHS.confD);

  // Search paths: configured module dir + local ./modules/
  const searchPaths = [
    moduleDir || PATHS.moduleDir,
    resolve(process.cwd(), 'modules'),
  ];

  // Also check for built-in modules relative to this package
  const builtinDir = resolve(__dirname || '.', '..', 'modules');
  if (existsSync(builtinDir)) {
    searchPaths.push(builtinDir);
  }

  for (const basePath of searchPaths) {
    if (!existsSync(basePath)) continue;

    const entries = readdirSync(basePath, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      const modPath = join(basePath, entry.name);
      const manifestPath = join(modPath, 'mod.toml');

      if (!existsSync(manifestPath)) continue;

      try {
        const raw = readFileSync(manifestPath, 'utf-8');
        const manifest = TOML.parse(raw) as unknown as ModuleManifest;
        const config = configs.get(manifest.module.name) || { enabled: true };

        modules.push({
          manifest: {
            name: manifest.module.name,
            version: manifest.module.version,
            description: manifest.module.description,
            author: manifest.module.author,
          },
          config,
          status: 'loaded',
          eventCount: 0,
          path: modPath,
        });
      } catch {
        // skip bad modules
      }
    }
  }

  return modules;
}

export function getBuiltinModulePaths(): string[] {
  return [
    resolve(__dirname || '.', '..', 'modules', 'log-watcher'),
    resolve(__dirname || '.', '..', 'modules', 'ssh-guard'),
  ];
}
