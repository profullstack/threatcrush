import { describe, expect, it } from "vitest";
import type { ScanFinding } from "@threatcrush/scan";
import {
  assertNoPrivateData,
  buildDescriptor,
  eligibleRepos,
  installationAnnounces,
  isSensitive,
  MAX_THREATS,
  repoKey,
  threatId,
  threatsFrom,
  type InstallationRow,
  type RepoRow,
  type ScanRow,
} from "../open-threats";

function finding(over: Partial<ScanFinding> = {}): ScanFinding {
  return {
    ruleId: "js-sql-string-building",
    title: "SQL assembled by concatenation",
    file: "src/db.ts",
    line: 12,
    severity: "high",
    confidence: "contextual",
    message: "A query is built from a string and a request value.",
    consequence: "Injection.",
    cwe: "CWE-89",
    excerpt: 'db.query("select * from users where id = " + req.query.id)',
    category: "code",
    ...over,
  };
}

const install = (id: number, over: Partial<InstallationRow> = {}): InstallationRow => ({
  installation_id: id,
  status: "active",
  announce: true,
  deleted_at: null,
  suspended_at: null,
  ...over,
});

const repo = (id: number, full_name: string, over: Partial<RepoRow> = {}): RepoRow => ({
  installation_id: id,
  full_name,
  private: false,
  removed_at: null,
  ...over,
});

const scan = (id: number, full_name: string, started_at: string, findings: ScanFinding[], over: Partial<ScanRow> = {}): ScanRow => ({
  installation_id: id,
  full_name,
  ref: "main",
  commit_sha: "abc123",
  status: "complete",
  findings,
  started_at,
  finished_at: started_at,
  ...over,
});

describe("installationAnnounces", () => {
  it("announces by default, including before the announce column exists", () => {
    expect(installationAnnounces(install(1))).toBe(true);
    expect(installationAnnounces(install(1, { announce: undefined }))).toBe(true);
    expect(installationAnnounces(install(1, { announce: null }))).toBe(true);
  });

  it("is silent when the installer turned it off, or the installation is gone", () => {
    expect(installationAnnounces(install(1, { announce: false }))).toBe(false);
    expect(installationAnnounces(install(1, { status: "deleted" }))).toBe(false);
    expect(installationAnnounces(install(1, { suspended_at: "2026-09-01T00:00:00Z" }))).toBe(false);
    expect(installationAnnounces(install(1, { deleted_at: "2026-09-01T00:00:00Z" }))).toBe(false);
  });
});

describe("eligibleRepos", () => {
  it("keeps public repositories on announcing installations only", () => {
    const allowed = eligibleRepos(
      [
        repo(1, "acme/open"),
        repo(1, "acme/secret", { private: true }),
        repo(1, "acme/gone", { removed_at: "2026-09-01T00:00:00Z" }),
        repo(2, "quiet/open"),
        repo(3, "orphan/open"),
      ],
      [install(1), install(2, { announce: false })]
    );
    expect(allowed).toEqual(new Set([repoKey(1, "acme/open")]));
  });
});

describe("threatsFrom", () => {
  it("publishes the latest scan's findings as open, with location and message for code findings", () => {
    const allowed = new Set([repoKey(1, "acme/open")]);
    const out = threatsFrom([scan(1, "acme/open", "2026-09-13T01:00:00Z", [finding()])], allowed);
    expect(out).toHaveLength(1);
    const t = out[0];
    expect(t.status).toBe("open");
    expect(t.kind).toBe("finding");
    expect(t.subject).toEqual({ name: "acme/open", url: "https://github.com/acme/open", ref: "main", commit: "abc123" });
    expect(t.location).toEqual({ file: "src/db.ts", line: 12 });
    expect(t.message).toContain("query");
    expect(t.rule).toBe("js-sql-string-building");
    expect(t.cwe).toBe("CWE-89");
    expect(t.tlp).toBe("clear");
    expect(t.id).toBe(threatId("acme/open", "js-sql-string-building", "src/db.ts"));
    expect(JSON.stringify(t)).not.toContain("excerpt");
  });

  it("withholds location, message, consequence and excerpt for secrets", () => {
    const allowed = new Set([repoKey(1, "acme/open")]);
    const secret = finding({
      ruleId: "secret-aws-access-key",
      title: "AWS access key",
      file: "config/prod.env",
      line: 3,
      category: "secret",
      sensitive: true,
      excerpt: "AWS_ACCESS_KEY_ID=AKIA...",
      message: "An AWS key on the line.",
    });
    const [t] = threatsFrom([scan(1, "acme/open", "2026-09-13T01:00:00Z", [secret])], allowed);
    expect(t.rule).toBe("secret-aws-access-key");
    expect(t.severity).toBe("high");
    expect(t.subject?.name).toBe("acme/open");
    expect(t.location).toBeUndefined();
    expect(t.message).toBeUndefined();
    expect(t.consequence).toBeUndefined();
    const text = JSON.stringify(t);
    expect(text).not.toContain("prod.env");
    expect(text).not.toContain("AKIA");
    expect(text).not.toContain("excerpt");
  });

  it("treats category secret as sensitive even without the flag", () => {
    expect(isSensitive({ category: "secret" })).toBe(true);
    expect(isSensitive({ category: "code", sensitive: true })).toBe(true);
    expect(isSensitive({ category: "code" })).toBe(false);
  });

  it("drops private repositories and installations that do not announce", () => {
    const allowed = eligibleRepos(
      [repo(1, "acme/open"), repo(1, "acme/secret", { private: true }), repo(2, "quiet/open")],
      [install(1), install(2, { announce: false })]
    );
    const out = threatsFrom(
      [
        scan(1, "acme/open", "2026-09-13T01:00:00Z", [finding()]),
        scan(1, "acme/secret", "2026-09-13T01:00:00Z", [finding({ file: "private.ts" })]),
        scan(2, "quiet/open", "2026-09-13T01:00:00Z", [finding({ file: "quiet.ts" })]),
      ],
      allowed
    );
    expect(out.map((t) => t.subject?.name)).toEqual(["acme/open"]);
    const text = JSON.stringify(out);
    expect(text).not.toContain("private.ts");
    expect(text).not.toContain("quiet.ts");
  });

  it("ignores scans that did not complete", () => {
    const allowed = new Set([repoKey(1, "acme/open")]);
    const out = threatsFrom(
      [scan(1, "acme/open", "2026-09-13T01:00:00Z", [finding()], { status: "running" })],
      allowed
    );
    expect(out).toEqual([]);
  });

  it("marks a finding fixed when a later scan no longer reports it, dated from both scans", () => {
    const allowed = new Set([repoKey(1, "acme/open")]);
    const gone = finding({ ruleId: "js-eval", file: "src/old.ts", title: "eval on input" });
    const out = threatsFrom(
      [
        scan(1, "acme/open", "2026-09-12T01:00:00Z", [finding(), gone], { commit_sha: "old1" }),
        scan(1, "acme/open", "2026-09-13T01:00:00Z", [finding({ line: 40 })], { commit_sha: "new1" }),
      ],
      allowed
    );
    const open = out.find((t) => t.status === "open");
    const fixed = out.find((t) => t.status === "fixed");
    expect(open?.rule).toBe("js-sql-string-building");
    expect(open?.location?.line).toBe(40);
    expect(open?.first_seen).toBe("2026-09-12T01:00:00Z");
    expect(open?.last_seen).toBe("2026-09-13T01:00:00Z");
    expect(fixed?.rule).toBe("js-eval");
    expect(fixed?.first_seen).toBe("2026-09-12T01:00:00Z");
    expect(fixed?.last_seen).toBe("2026-09-13T01:00:00Z");
    expect(fixed?.subject?.commit).toBe("old1");
    expect(fixed?.count).toBe(0);
  });

  it("counts several lines of one rule in one file as one threat", () => {
    const allowed = new Set([repoKey(1, "acme/open")]);
    const [t] = threatsFrom(
      [scan(1, "acme/open", "2026-09-13T01:00:00Z", [finding({ line: 1 }), finding({ line: 9 })])],
      allowed
    );
    expect(t.count).toBe(2);
    expect(t.location?.line).toBe(1);
  });
});

describe("buildDescriptor", () => {
  it("names the reporter, the version and caps the list", () => {
    const allowed = new Set([repoKey(1, "acme/open")]);
    const many = Array.from({ length: MAX_THREATS + 5 }, (_, i) => finding({ file: `f${i}.ts` }));
    const d = buildDescriptor(threatsFrom([scan(1, "acme/open", "2026-09-13T01:00:00Z", many)], allowed));
    expect(d.openthreat).toBe("0.1");
    expect(d.reporter.name).toBe("ThreatCrush");
    expect(d.reporter.tool).toBe("threatcrush");
    expect(d.threats).toHaveLength(MAX_THREATS);
    expect(d.truncated).toBe(true);
    expect(() => assertNoPrivateData(d)).not.toThrow();
  });

  it("refuses a descriptor that carries a private key", () => {
    const d = buildDescriptor([]);
    const leaky = { ...d, threats: [{ ...d.threats[0], installation_id: 5 } as never] };
    expect(() => assertNoPrivateData(leaky as typeof d)).toThrow(/installation_id/);
  });
});
