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

  it("treats desktop clients differently from Linux server installs", () => {
    expect(installScript).toContain('DESKTOP_PKG_NAME="@profullstack/threatcrush-desktop"');
    expect(installScript).toContain('desktop-client');
    expect(installScript).toContain('Linux server');
    expect(installScript).toContain('install_desktop_bundle');
  });
});
