import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({}) }));
import { buildPage } from "../notify";

const inc = (summary: string, title = "Critical System Error") => ({
  id: "i1", org_id: "o1", team_id: null, title, severity: "critical", host: "dev2.profullstack.com", summary, findings_count: 1,
});

describe("incident page text", () => {
  it("says what happened, not just the rule", () => {
    const m = buildPage(inc("sudo: pam_unix(sudo:auth): auth could not identify password for [anthony]\n\nCritical or emergency level system log message (1 events in 60s)") as never, "profullstack");
    expect(m.sms).toBe("[ThreatCrush CRITICAL] Critical System Error on dev2.profullstack.com: sudo: pam_unix(sudo:auth): auth could not identify password for [anthony]. 1 finding. https://threatcrush.com/org/profullstack/incidents/i1");
    expect(m.text).toContain("could not identify password");
  });

  it("stays within SMS length by cutting the detail, keeping the link", () => {
    const m = buildPage(inc("x".repeat(1000)) as never, "profullstack");
    expect(m.sms.length).toBeLessThanOrEqual(320);
    expect(m.sms).toContain("…");
    expect(m.sms.endsWith("/incidents/i1")).toBe(true);
  });

  it("does not repeat the title when the summary is just the title", () => {
    expect(buildPage(inc("Critical System Error") as never, null).sms).toBe("[ThreatCrush CRITICAL] Critical System Error on dev2.profullstack.com. 1 finding. https://threatcrush.com/dashboard");
  });
});
