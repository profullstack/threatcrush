import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const repoRoot = join(__dirname, "..", "..");

function read(relPath: string) {
  return readFileSync(join(repoRoot, relPath), "utf8");
}

describe("docs pages", () => {
  it("/docs page separates supported commands from planned work", () => {
    const page = read("src/app/docs/page.tsx");

    expect(page).toContain("ThreatCrush Docs");
    expect(page).toContain("Commands we support today");
    expect(page).toContain("Planned / not fully implemented yet");
    expect(page).toContain("threatcrush update");
    expect(page).toContain("threatcrush remove");
    expect(page).toContain("threatcrush store publish <url>");
    expect(page).toContain("Supported surface");
  });

  it("homepage links people to the docs page, promotes the store, and uses a mobile menu", () => {
    const page = read("src/app/page.tsx");

    expect(page).toContain('href="/docs"');
    expect(page).toContain("Read the docs →");
    expect(page).toContain("Explore Module Store");
    expect(page).toContain('href="/store/publish"');
  });

  it("/docs/modules page documents module author contribution flow", () => {
    const page = read("src/app/docs/modules/page.tsx");

    expect(page).toContain("Module Author Docs");
    expect(page).toContain("How module contribution works today");
    expect(page).toContain("Supported contributor flow");
    expect(page).toContain("Required");
    expect(page).toContain("Recommended");
    expect(page).toContain("Planned module-author features");
    expect(page).toContain("/store/publish");
    expect(page).toContain("threatcrush.com/store");
  });

  it("/docs page also frames the store as the first destination", () => {
    const page = read("src/app/docs/page.tsx");

    expect(page).toContain("Module Store");
    expect(page).toContain("Why the marketplace matters first");
    expect(page).toContain("/docs/modules");
    expect(page).toContain("/store/publish");
  });
});
