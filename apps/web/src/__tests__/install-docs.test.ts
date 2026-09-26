import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// __dirname is apps/web/src/__tests__ — go up four levels for the monorepo root.
const repoRoot = join(__dirname, "..", "..", "..", "..");

function read(relPath: string) {
  return readFileSync(join(repoRoot, relPath), "utf8");
}

describe("install/update docs messaging", () => {
  it("root README promotes curl pipe sh as the preferred install", () => {
    const readme = read("README.md");

    expect(readme).toContain("**Preferred install:**");
    expect(readme).toContain("curl -fsSL https://threatcrush.com/install.sh | sh");
    expect(readme).toContain("threatcrush update");
    expect(readme).toContain("threatcrush remove");
    expect(readme).toContain("**Linux server** → installs the CLI");
  });

  it("CLI README promotes curl pipe sh and correct platform messaging", () => {
    const readme = read("apps/cli/README.md");

    expect(readme).toContain("**Preferred install:**");
    expect(readme).toContain("curl -fsSL https://threatcrush.com/install.sh | sh");
    expect(readme).toContain("threatcrush update");
    expect(readme).toContain("threatcrush remove");
    expect(readme).toContain("**Linux server** → installs the CLI");
  });
});
