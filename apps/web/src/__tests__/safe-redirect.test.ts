import { describe, expect, it } from "vitest";
import { safeRedirectPath } from "@/lib/safe-redirect";

describe("safeRedirectPath", () => {
  it("preserves internal paths, queries, and fragments", () => {
    expect(safeRedirectPath("/usage?range=30d#details")).toBe(
      "/usage?range=30d#details"
    );
  });

  it.each([
    "https://attacker.example/phish",
    "//attacker.example/phish",
    "/\\attacker.example/phish",
    "javascript:alert(1)",
    "account",
  ])("rejects unsafe redirect %s", (value) => {
    expect(safeRedirectPath(value)).toBe("/account");
  });

  it("uses the requested fallback for missing values", () => {
    expect(safeRedirectPath(null, "/")).toBe("/");
  });
});
