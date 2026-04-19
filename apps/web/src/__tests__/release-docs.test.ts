import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const repoRoot = join(__dirname, "..", "..");

describe("release docs and mobile workflow", () => {
  it("adds an Expo/EAS mobile release workflow", () => {
    const workflow = readFileSync(join(repoRoot, ".github/workflows/mobile-release.yml"), "utf8");

    expect(workflow).toContain("name: Mobile Release");
    expect(workflow).toContain("expo/expo-github-action@v8");
    expect(workflow).toContain("eas build");
    expect(workflow).toContain("EXPO_TOKEN");
  });

  it("avoids hard failing docker releases when Docker Hub auth is unavailable", () => {
    const workflow = readFileSync(join(repoRoot, ".github/workflows/docker-publish.yml"), "utf8");

    expect(workflow).toContain("Build and push to GHCR");
    expect(workflow).toContain("Build and push to Docker Hub + GHCR");
    expect(workflow).toContain("if: env.DOCKER_USERNAME == ''");
    expect(workflow).toContain("ghcr.io/profullstack/threatcrush:latest");
  });

  it("documents release automation in /docs/releases", () => {
    const page = readFileSync(join(repoRoot, "src/app/docs/releases/page.tsx"), "utf8");

    expect(page).toContain("Release Automation");
    expect(page).toContain("Mobile Release");
    expect(page).toContain("Desktop Release");
    expect(page).toContain("EXPO_TOKEN");
    expect(page).toContain("workflow definitions");
    expect(page).toContain("docs/MOBILE_RELEASE_TODO.md");
    expect(page).toContain("docs/DESKTOP_RELEASE_TODO.md");
  });

  it("captures release TODOs directly in the repo docs folder", () => {
    const mobileTodo = readFileSync(join(repoRoot, "docs/MOBILE_RELEASE_TODO.md"), "utf8");
    const desktopTodo = readFileSync(join(repoRoot, "docs/DESKTOP_RELEASE_TODO.md"), "utf8");
    const releaseStatus = readFileSync(join(repoRoot, "docs/RELEASE_STATUS.md"), "utf8");

    expect(mobileTodo).toContain("Ship real native mobile builds for ThreatCrush using Expo / EAS");
    expect(desktopTodo).toContain("Package desktop app");
    expect(releaseStatus).toContain("Desktop Release workflow is active but currently fails in `Package desktop app`");
    expect(releaseStatus).toContain("Docker Publish workflow was active");
  });
});
