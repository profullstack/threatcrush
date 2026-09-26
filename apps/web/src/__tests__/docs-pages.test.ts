import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const repoRoot = join(__dirname, "..", "..");

function read(relPath: string) {
  return readFileSync(join(repoRoot, relPath), "utf8");
}

describe("docs pages", () => {
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
});
