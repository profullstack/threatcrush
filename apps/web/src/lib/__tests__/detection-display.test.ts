import { describe, expect, it } from "vitest";
import { detectionUsername, isSshDetection } from "@/lib/detection-display";

describe("detection display helpers", () => {
  it("uses the normalized username when the API has one", () => {
    const detection = {
      rule_id: "ssh-success-after-failures",
      username: "anthony",
      raw_metadata: { evidence: { module: "ssh-guard", message: "SSH login accepted for old-user" } },
    };

    expect(detectionUsername(detection)).toBe("anthony");
    expect(isSshDetection(detection)).toBe(true);
  });

  it("recovers a missing SSH username from preserved evidence", () => {
    expect(detectionUsername({
      rule_id: "ssh-success-after-failures",
      username: null,
      raw_metadata: { evidence: { module: "ssh-guard", message: "SSH login accepted for anthony" } },
    })).toBe("anthony");

    expect(detectionUsername({
      rule_id: "ssh-brute-force",
      raw_metadata: { evidence: { module: "ssh-guard", message: "Invalid SSH user: deploy from 203.0.113.8" } },
    })).toBe("deploy");
  });

  it("does not infer usernames from unrelated event text", () => {
    expect(detectionUsername({
      rule_id: "web-sqli",
      raw_metadata: { evidence: { module: "nginx", message: "SSH login accepted for example" } },
    })).toBeNull();
    expect(isSshDetection({ rule_id: "web-sqli", raw_metadata: { evidence: { module: "nginx" } } })).toBe(false);
  });
});
