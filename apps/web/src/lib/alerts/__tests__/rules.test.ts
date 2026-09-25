import { describe, expect, it } from "vitest";
import { ruleMatches } from "../rules";
import type { AlertableDetection, AlertDestinationRow, AlertRuleRow } from "../types";

const rule = (overrides: Partial<AlertRuleRow> = {}): AlertRuleRow => ({
  id: "rule-1",
  organization_id: "org-1",
  name: "High",
  min_severity: "high",
  server_scope: [],
  destination_id: "dest-1",
  rate_limit_per_hour: 60,
  enabled: true,
  ...overrides,
});

const destination = (overrides: Partial<AlertDestinationRow> = {}): AlertDestinationRow => ({
  id: "dest-1",
  organization_id: "org-1",
  name: "Slack",
  type: "slack",
  config: {},
  enabled: true,
  ...overrides,
});

const detection = (overrides: Partial<AlertableDetection> = {}): AlertableDetection => ({
  id: "det-1",
  organization_id: "org-1",
  server_id: "srv-1",
  severity: "high",
  title: "SSH brute force",
  description: null,
  source_ip: "203.0.113.5",
  rule_id: "ssh-bruteforce",
  detected_at: "2026-09-25T10:00:00.000Z",
  ...overrides,
});

describe("ruleMatches", () => {
  it("fires at exactly the minimum severity and above, not below", () => {
    expect(ruleMatches(rule(), destination(), detection({ severity: "high" }))).toBe(true);
    expect(ruleMatches(rule(), destination(), detection({ severity: "critical" }))).toBe(true);
    expect(ruleMatches(rule(), destination(), detection({ severity: "medium" }))).toBe(false);
    expect(ruleMatches(rule({ min_severity: "info" }), destination(), detection({ severity: "info" }))).toBe(true);
  });

  it("treats an empty or missing server scope as every server", () => {
    expect(ruleMatches(rule({ server_scope: [] }), destination(), detection())).toBe(true);
    expect(ruleMatches(rule({ server_scope: null }), destination(), detection())).toBe(true);
  });

  it("limits a scoped rule to the listed servers", () => {
    const scoped = rule({ server_scope: ["srv-2", "srv-3"] });
    expect(ruleMatches(scoped, destination(), detection({ server_id: "srv-3" }))).toBe(true);
    expect(ruleMatches(scoped, destination(), detection({ server_id: "srv-1" }))).toBe(false);
  });

  it("never fires a disabled rule or into a disabled or missing destination", () => {
    expect(ruleMatches(rule({ enabled: false }), destination(), detection())).toBe(false);
    expect(ruleMatches(rule(), destination({ enabled: false }), detection())).toBe(false);
    expect(ruleMatches(rule(), undefined, detection())).toBe(false);
  });

  it("never crosses organizations", () => {
    expect(ruleMatches(rule(), destination({ organization_id: "org-2" }), detection())).toBe(false);
    expect(ruleMatches(rule({ organization_id: "org-2" }), destination(), detection())).toBe(false);
  });

  it("ignores severities it does not know", () => {
    const odd = detection({ severity: "constructor" as AlertableDetection["severity"] });
    expect(ruleMatches(rule({ min_severity: "info" }), destination(), odd)).toBe(false);
  });
});
