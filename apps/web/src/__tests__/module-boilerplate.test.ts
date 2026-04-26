import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";

// __dirname is apps/web/src/__tests__ — go up four levels for the monorepo root.
const repoRoot = path.resolve(__dirname, "..", "..", "..", "..");
const boilerplateDir = path.join(repoRoot, "boilerplates/module-example");
const read = (relativePath: string) =>
  fs.readFileSync(path.join(boilerplateDir, relativePath), "utf8");

describe("module boilerplate", () => {
  it("contains the expected starter files", () => {
    const expected = [
      "README.md",
      "mod.toml",
      "package.json",
      "tsconfig.json",
      ".gitignore",
      "src/index.ts",
      "config/example.conf.toml",
    ];

    for (const file of expected) {
      expect(fs.existsSync(path.join(boilerplateDir, file))).toBe(true);
    }
  });

  it("includes a manifest with required marketplace fields", () => {
    const modToml = read("mod.toml");

    expect(modToml).toContain("[module]");
    expect(modToml).toContain("name = ");
    expect(modToml).toContain("version = ");
    expect(modToml).toContain("description = ");
    expect(modToml).toContain("author = ");
    expect(modToml).toContain("license = ");
    expect(modToml).toContain("homepage = ");
    expect(modToml).toContain("[module.pricing]");
    expect(modToml).toContain("type = ");
    expect(modToml).toContain("[module.requirements]");
    expect(modToml).toContain("threatcrush = ");
  });

  it("includes a runnable TypeScript starter module", () => {
    const indexTs = read("src/index.ts");

    expect(indexTs).toContain("export default class ExampleAlertModule");
    expect(indexTs).toContain("async init(");
    expect(indexTs).toContain("async start(");
    expect(indexTs).toContain("async onEvent(");
    expect(indexTs).toContain("async stop(");
  });

  it("documents clone, rename, and publish flow", () => {
    const readme = read("README.md");

    expect(readme).toContain("Clone this boilerplate");
    expect(readme).toContain("Rename it");
    expect(readme).toContain("Publishing checklist");
    expect(readme).toContain("https://threatcrush.com/store/publish");
  });
});
