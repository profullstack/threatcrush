import { describe, expect, it, vi } from "vitest";
import { banner } from "../logger.js";
import { PKG_VERSION } from "../version.js";

describe("banner", () => {
  // The bug this file exists for: the banner printed a hardcoded
  // "v0.1.0" on every command, so a box running 0.11.6 reported a version
  // ten minors stale and looked like a failed upgrade.
  it("reports the resolved package version, not a literal", () => {
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args) => {
      lines.push(args.join(" "));
    });

    try {
      banner();
    } finally {
      spy.mockRestore();
    }

    const versionLine = lines.find((l) => l.includes("All-in-one security agent daemon"));
    expect(versionLine).toBeDefined();
    expect(versionLine).toContain(`v${PKG_VERSION}`);
    expect(versionLine).not.toContain("v0.1.0");
  });
});
