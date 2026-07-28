/**
 * Dependency and supply-chain scanning — the `deps` subsystem of
 * `code-scanner`.
 *
 * Implements PRD 0002, which originally proposed this as a standalone
 * `dep-scanner` module and left the boundary open. It is folded in here
 * because `PRD.md` already assigns "dependency CVEs" to `code-scanner`, and a
 * separate module would have meant two things scanning the same directories,
 * holding two inventories of the same tree, and two places for an operator to
 * configure a path list.
 *
 * The subsystem keeps its own directory rather than dissolving into the
 * module: it owns an external advisory database, a per-ecosystem parser
 * surface that will keep growing, and a detection model (a package graph)
 * that has nothing in common with the source-level scanning `code-scanner`
 * will add for secrets and SAST. Those are separable concerns that happen to
 * share a filesystem walk.
 */

export * from './inventory.js';
export * from './osv.js';
export * from './scripts.js';
export * from './semver.js';

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { buildInventory, type Inventory } from './inventory.js';
import { queryAdvisories, severityRank, type Finding } from './osv.js';
import { extractScripts, rankScripts, type ScriptVerdict } from './scripts.js';

export interface DepsOptions {
  paths: readonly string[];
  maxDepth: number;
  advisories: boolean;
  installScripts: boolean;
  /** `rank_down` demotes dev-only findings; `equal` leaves them alone. */
  devDependencies: 'rank_down' | 'equal';
  /** Called when advisory lookup fails, so the caller can surface it. */
  onDegraded?: (reason: string) => void;
}

export interface DepsResult {
  inventory: Inventory;
  findings: Finding[];
  scripts: ScriptVerdict[];
  drift: { root: string; name: string; locked: string; installed: string }[];
  /** True when any root failed to parse — the caller must not report "clean". */
  incomplete: boolean;
}

export const DEPS_DEFAULTS: DepsOptions = {
  paths: ['/srv', '/var/www', '/opt'],
  maxDepth: 4,
  advisories: true,
  installScripts: true,
  devDependencies: 'rank_down',
};

/** One step down the severity ladder, floored at low. */
export function demote(severity: Finding['severity']): Finding['severity'] {
  const order: Finding['severity'][] = ['info', 'low', 'medium', 'high', 'critical'];
  return order[Math.max(1, order.indexOf(severity) - 1)]!;
}

/**
 * Run the whole dependency pass: inventory, advisories, install scripts, drift.
 *
 * Pure with respect to the daemon — it takes options and returns a result,
 * with no `ModuleContext` — so the same entry point serves the scheduled
 * daemon scan and the one-shot `threatcrush scan --deps`.
 */
export async function scanDependencies(options: DepsOptions): Promise<DepsResult> {
  const inventory = await buildInventory(options.paths, options.maxDepth);
  const scripts = options.installScripts ? await collectInstallScripts(inventory) : [];

  let findings: Finding[] = [];
  if (options.advisories && inventory.packages.length > 0) {
    try {
      findings = await queryAdvisories(
        inventory.packages.map((p) => ({ name: p.name, version: p.version })),
      );
    } catch (err) {
      // Advisory lookup is the only part needing the network. Losing it must
      // degrade the scan, not void it — and must be visible, because a silent
      // skip is indistinguishable from "nothing found".
      options.onDegraded?.(String(err));
      inventory.incomplete = true;
    }
  }

  // Dev-only findings are ranked down, never dropped (PRD 0002 R9).
  if (options.devDependencies !== 'equal') {
    const devOnly = new Set(
      inventory.packages.filter((p) => p.dev).map((p) => `${p.name}@${p.version}`),
    );
    findings = findings.map((f) =>
      devOnly.has(`${f.package}@${f.version}`) && severityRank(f.severity) > 1
        ? { ...f, severity: demote(f.severity) }
        : f,
    );
  }

  const drift = inventory.roots.flatMap((root) =>
    root.drift.map((entry) => ({ root: root.root, ...entry })),
  );

  return { inventory, findings, scripts, drift, incomplete: inventory.incomplete };
}

/** Read lifecycle scripts out of every installed package and score them. */
async function collectInstallScripts(inventory: Inventory): Promise<ScriptVerdict[]> {
  const scripts = [];

  for (const report of inventory.roots) {
    for (const record of report.packages) {
      if (!record.path.startsWith('node_modules')) continue;
      try {
        const manifest = JSON.parse(
          await readFile(join(report.root, record.path, 'package.json'), 'utf8'),
        ) as { name?: string; version?: string; scripts?: Record<string, string> };
        scripts.push(...extractScripts(manifest, record.name));
      } catch {
        // A package whose manifest cannot be read contributes no scripts; the
        // root's own parse status already records the trouble.
      }
    }
  }

  return rankScripts(scripts);
}
