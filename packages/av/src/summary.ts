import type { AvEngine, AvFileResult, AvSummary } from './types';

export function summarize(results: AvFileResult[], engines: AvEngine[], startedAt: Date, skipped = 0): AvSummary {
  const count = (v: AvFileResult['verdict']) => results.filter((r) => r.verdict === v).length;
  return {
    scanned: results.length,
    malicious: count('malicious'),
    suspicious: count('suspicious'),
    clean: count('clean'),
    errors: count('error'),
    skipped,
    engines,
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
  };
}
