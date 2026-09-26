import {
  SEVERITY_RANK,
  type AlertableDetection,
  type AlertDestinationRow,
  type AlertRuleRow,
  type Severity,
} from "./types";

/**
 * Whether `rule` should fire for `detection`. The destination must exist, be
 * enabled and belong to the same org; anything else means the rule is dead.
 * An empty (or missing) server_scope means "every server in the org".
 */
export function ruleMatches(
  rule: AlertRuleRow,
  destination: AlertDestinationRow | undefined,
  detection: AlertableDetection,
): boolean {
  if (!rule.enabled || rule.organization_id !== detection.organization_id) return false;
  if (!destination || !destination.enabled) return false;
  if (destination.organization_id !== detection.organization_id) return false;

  const detectionRank = SEVERITY_RANK[detection.severity as Severity];
  const threshold = SEVERITY_RANK[rule.min_severity as Severity];
  if (typeof detectionRank !== "number" || typeof threshold !== "number") return false;
  if (detectionRank < threshold) return false;

  const scope = rule.server_scope;
  if (!Array.isArray(scope) || scope.length === 0) return true;
  return scope.includes(detection.server_id);
}
