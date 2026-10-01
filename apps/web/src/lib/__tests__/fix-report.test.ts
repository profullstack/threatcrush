import { describe, expect, it } from "vitest";
import { buildFixReport, renderFixPrompt } from "@/lib/fix-report";

const org = { name: "Profullstack", slug: "profullstack" };
const servers = [
  { id: "s1", name: "dev2", hostname: "user", threatcrushd_version: "0.13.15", last_seen: "2026-10-01T10:30:00Z" },
  { id: "s2", name: "seed1", hostname: "ubuntu", threatcrushd_version: "0.13.15", last_seen: "2026-10-01T10:30:00Z" },
];
const findings = [
  { server_id: "s1", finding_key: "ssh-weak-config", severity: "medium", status: "warn", title: "SSH allows weak ciphers", recommendation: "Remove CBC ciphers from sshd_config", observed_at: "2026-10-01T10:00:00Z" },
  { server_id: "s1", finding_key: "auto-updates", severity: "high", status: "fail", title: "Automatic security updates are off", recommendation: "apt install unattended-upgrades", observed_at: "2026-10-01T10:00:00Z" },
];
const detections = [
  { title: "Path Traversal Attack Detected", severity: "high", source_ip: "45.138.12.22", occurrences: 3 },
  { title: "Path Traversal Attack Detected", severity: "high", source_ip: "93.152.221.226", occurrences: 1 },
  { title: "Exploit Probe Pattern", severity: "high", source_ip: "45.138.12.22", occurrences: 1 },
];

describe("buildFixReport", () => {
  it("groups open findings by server, worst first, and summarizes attacks", () => {
    const r = buildFixReport(org, servers, findings, detections, new Date("2026-10-01T10:31:00Z"));
    expect(r.open_findings).toBe(2);
    expect(r.servers[0].name).toBe("dev2");
    expect(r.servers[0].findings.map((f) => f.key)).toEqual(["auto-updates", "ssh-weak-config"]);
    expect(r.detections.total).toBe(5);
    expect(r.detections.top[0]).toEqual({ title: "Path Traversal Attack Detected", severity: "high", count: 4, sources: 2 });
    expect(r.detections.top_sources[0]).toEqual({ ip: "45.138.12.22", count: 4 });
  });
});

describe("renderFixPrompt", () => {
  const prompt = renderFixPrompt(buildFixReport(org, servers, findings, detections));

  it("tells the agent how to fix, verify, and what not to touch", () => {
    expect(prompt).toContain("threatcrush harden");
    expect(prompt).toContain("back up any file");
    expect(prompt).toContain("Do not unban or allowlist");
  });

  it("lists every open finding with its fix, under its server", () => {
    expect(prompt).toContain("### dev2 (user)");
    expect(prompt).toContain("**[high] Automatic security updates are off** (`auto-updates`, fail)");
    expect(prompt).toContain("Fix: apt install unattended-upgrades");
    expect(prompt).toContain("No open findings: seed1.");
  });

  it("says so plainly when there is nothing to fix", () => {
    const empty = renderFixPrompt(buildFixReport(org, servers, [], []));
    expect(empty).toContain("None. Every hardening check passes on every server.");
    expect(empty).toContain("No detections.");
  });

  it("never uses em or en dashes", () => {
    expect(prompt).not.toMatch(/[–—]/);
  });
});
