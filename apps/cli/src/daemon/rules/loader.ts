import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { DetectionRule } from './engine.js';
import { DEFAULT_RULES } from './default-rules.js';

const RULES_DIR = '/etc/threatcrush/rules.d';

export function loadAllRules(customDir?: string): DetectionRule[] {
  const rules = [...DEFAULT_RULES];
  const dir = customDir || RULES_DIR;

  if (existsSync(dir)) {
    const files = readdirSync(dir).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const raw = readFileSync(join(dir, file), 'utf-8');
        const parsed = JSON.parse(raw);
        const customRules: DetectionRule[] = Array.isArray(parsed) ? parsed : [parsed];
        for (const rule of customRules) {
          if (!rule.id || !rule.title || !rule.match) {
            console.warn(`[rules] skipping invalid rule in ${file}: missing required fields`);
            continue;
          }
          const existingIdx = rules.findIndex(r => r.id === rule.id);
          if (existingIdx >= 0) {
            rules[existingIdx] = { ...rules[existingIdx], ...rule };
          } else {
            rules.push(rule);
          }
        }
      } catch (err) {
        console.warn(`[rules] failed to load ${file}: ${(err as Error).message}`);
      }
    }
  }

  return rules;
}
