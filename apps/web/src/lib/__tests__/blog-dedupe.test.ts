import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { duplicateOf, type Existing } from "../blog-dedupe";

const existing: Existing[] = [
  { slug: "ci-cd-security-threat-detection", title: "CI/CD Security Threat Detection: An Operational Architecture for the SOC", source: "crawlproof", source_id: "a1" },
  { slug: "detection-engineering-pricing", title: "Detection Engineering Pricing in 2026: A Practical Cost Guide", source: "crawlproof", source_id: "a2" },
];
const none = new Map<string, string>();
const post = (slug: string, title: string, source_id = "new") => ({ slug, title, source: "crawlproof", source_id });

describe("duplicateOf", () => {
  it("refuses a collision-suffixed copy of an existing topic", () => {
    for (const slug of ["ci-cd-security-threat-detection-2", "ci-cd-security-threat-detection-hl4w"]) {
      expect(duplicateOf(post(slug, "Anything"), existing, none), slug).toBe("ci-cd-security-threat-detection");
    }
  });

  it("refuses a new slug whose title only reframes the subtitle", () => {
    expect(duplicateOf(post("ci-cd-pipeline-soc-model", "CI/CD Security Threat Detection: An Operating Model"), existing, none))
      .toBe("ci-cd-security-threat-detection");
  });

  it("refuses a merged slug coming back", () => {
    const merged = new Map([["ci-cd-security-threat-detection-6", "ci-cd-security-threat-detection"]]);
    expect(duplicateOf(post("ci-cd-security-threat-detection-6", "x", "a9"), existing, merged)).toBe("ci-cd-security-threat-detection");
  });

  it("lets a redelivery of the same article and a new topic through", () => {
    expect(duplicateOf(post("ci-cd-security-threat-detection", "CI/CD Security Threat Detection: v2", "a1"), existing, none)).toBeNull();
    expect(duplicateOf(post("detection-engineering-metrics", "Detection Engineering Metrics That Matter"), existing, none)).toBeNull();
  });
});
