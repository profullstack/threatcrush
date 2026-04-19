import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const repoRoot = join(__dirname, "..", "..");

describe("usage page auth gating", () => {
  it("wraps with AuthProvider for client-side auth check", () => {
    const page = readFileSync(join(repoRoot, "src/app/usage/page.tsx"), "utf8");

    expect(page).toContain("AuthProvider");
    expect(page).toContain("UsageContent");
  });

  it("usage-content redirects to login when not signed in", () => {
    const content = readFileSync(join(repoRoot, "src/app/usage/usage-content.tsx"), "utf8");

    expect(content).toContain("/auth/login?next=/usage");
    expect(content).toContain("useAuth");
    expect(content).toContain("signedIn");
  });
});
