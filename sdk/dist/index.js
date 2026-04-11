/**
 * ThreatCrush Module SDK
 *
 * Unified type definitions for building ThreatCrush security modules.
 * Merges the CLI module contract with the marketplace boilerplate capabilities.
 *
 * Usage:
 *   import type { ThreatCrushModule, ModuleContext, ThreatEvent } from '@threatcrush/sdk';
 */
// ─── Helpers ───
/** Normalize a phone number to E.164 format */
export function normalizePhone(raw) {
    const digits = raw.replace(/[^\d+]/g, '');
    if (digits.startsWith('+'))
        return digits;
    if (digits.length === 10)
        return `+1${digits}`;
    return `+${digits}`;
}
/** Severity label to ANSI color code */
export function severityAnsi(severity) {
    const codes = {
        info: '\x1b[32m', // green
        low: '\x1b[36m', // cyan
        medium: '\x1b[33m', // yellow
        high: '\x1b[31m', // red
        critical: '\x1b[35m', // magenta
    };
    return codes[severity] || '';
}
//# sourceMappingURL=index.js.map