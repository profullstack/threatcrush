import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const repoRoot = join(__dirname, "..", "..");
const installScript = readFileSync(join(repoRoot, "public", "install.sh"), "utf8");

describe("install.sh", () => {
  it("documents the blessed curl pipe sh install path", () => {
    expect(installScript).toContain("curl -fsSL https://threatcrush.com/install.sh | sh");
  });

  it("can bootstrap bare machines with mise", () => {
    expect(installScript).toContain("MISE_INSTALL_URL=\"https://mise.run\"");
    expect(installScript).toContain("install_mise()");
    expect(installScript).toContain("mise use -g node@lts");
  });

  it("detects whether the machine is server or desktop and records platform kind", () => {
    expect(installScript).toContain("detect_install_mode()");
    expect(installScript).toContain("DISPLAY");
    expect(installScript).toContain("WAYLAND_DISPLAY");
    expect(installScript).toContain("SSH_CONNECTION");
    expect(installScript).toContain("PLATFORM_KIND");
    expect(installScript).toContain("desktop-client");
    expect(installScript).toContain("linux-server");
    expect(installScript).toContain("write_install_config");
  });

  it("frames threatcrush update/remove as the supported lifecycle path", () => {
    expect(installScript).toContain("threatcrush update");
    expect(installScript).toContain("threatcrush remove");
    expect(installScript).toContain("Platform kind:");
  });

  it("installs the CLI on every platform, including macOS and Windows", () => {
    // Regression: the desktop-client branch skipped the CLI entirely and tried
    // to `add -g @profullstack/threatcrush-desktop`, which has never been
    // published. Under `set -e` the 404 aborted the whole install on macOS.
    expect(installScript).toContain('install_global_package "$PKG_NAME"');
    expect(installScript).not.toContain("@profullstack/threatcrush-desktop");
  });

  it("points desktop users at the GitHub Releases bundle", () => {
    expect(installScript).toContain("DESKTOP_RELEASES_URL");
    expect(installScript).toContain("releases/latest");
    expect(installScript).toContain("announce_desktop_bundle");
    expect(installScript).toContain("desktop-client");
  });
});
