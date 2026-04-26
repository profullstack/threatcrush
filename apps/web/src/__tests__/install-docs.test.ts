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
    expect(readme).toContain("bootstrap Node.js with `mise`");
    expect(readme).toContain("**Linux server** → installs the CLI");
    expect(readme).toContain("**Linux desktop** → installs the CLI + desktop app");
    expect(readme).toContain("**Windows desktop** → installs the desktop app to connect to a ThreatCrush server elsewhere");
  });

  it("CLI README promotes curl pipe sh and correct platform messaging", () => {
    const readme = read("apps/cli/README.md");

    expect(readme).toContain("**Preferred install:**");
    expect(readme).toContain("curl -fsSL https://threatcrush.com/install.sh | sh");
    expect(readme).toContain("threatcrush update");
    expect(readme).toContain("threatcrush remove");
    expect(readme).toContain("bootstrap Node.js with `mise`");
    expect(readme).toContain("**Linux server** → installs the CLI");
    expect(readme).toContain("**Linux desktop** → installs the CLI + desktop app");
    expect(readme).toContain("**Windows desktop** → installs the desktop app to connect to a ThreatCrush server elsewhere");
  });

  it("homepage copy reflects server-hosted Linux and desktop-client Windows", () => {
    const homePage = read("apps/web/src/app/page.tsx");

    expect(homePage).toContain("curl -fsSL https://threatcrush.com/install.sh | sh");
    expect(homePage).toContain("threatcrush update");
    expect(homePage).toContain("threatcrush remove");
    expect(homePage).toContain("server</span> or <span className=\"text-tc-green\">desktop");
    expect(homePage).toContain("Windows is desktop-client only");
    expect(homePage).toContain("Linux servers run the real monitoring/daemon stack");
    expect(homePage).toContain("bootstrap Node.js with");
    expect(homePage).toContain(">mise<");
  });
});
