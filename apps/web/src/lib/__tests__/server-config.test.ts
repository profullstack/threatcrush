import { describe, expect, it } from "vitest";
import { REDACTED, redactConfig } from "@/lib/server-config";

describe("redactConfig", () => {
  it("keeps remediation settings and strips alert secrets", () => {
    const out = redactConfig({
      remediation: { max_ban: "7d", strike_memory: "30d", enabled: true },
      alerts: {
        smtp: { host: "smtp.example.com", password: "hunter2", enabled: true },
        slack: { webhook_url: "https://hooks.slack.com/x" },
        pagerduty: { routing_key: "abc" },
      },
    });
    expect(out).toEqual({
      remediation: { max_ban: "7d", strike_memory: "30d", enabled: true },
      alerts: {
        smtp: { host: "smtp.example.com", password: REDACTED, enabled: true },
        slack: { webhook_url: REDACTED },
        pagerduty: { routing_key: REDACTED },
      },
    });
  });

  it("redacts inside arrays", () => {
    expect(redactConfig({ hooks: [{ token: "t", name: "a" }] })).toEqual({ hooks: [{ token: REDACTED, name: "a" }] });
  });
});
