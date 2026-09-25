import { beforeEach, describe, expect, it, vi } from "vitest";

const mockSafeFetch = vi.fn();
const mockLookup = vi.fn();

vi.mock("@/lib/ssrf-guard", () => ({
  safeFetch: (...args: unknown[]) => mockSafeFetch(...args),
}));
vi.mock("dns/promises", () => ({
  default: { lookup: (...args: unknown[]) => mockLookup(...args) },
}));

import { checkModuleSource } from "@/lib/module-source-health";

function respond(status: number, contentType = "text/plain") {
  return new Response("", { status, headers: { "content-type": contentType } });
}

const GIT_ADVERTISEMENT = "application/x-git-upload-pack-advertisement";

describe("checkModuleSource", () => {
  beforeEach(() => {
    mockSafeFetch.mockReset();
    mockLookup.mockReset().mockResolvedValue({ address: "93.184.216.34", family: 4 });
  });

  it("marks a clonable git repository ok, probing the ref advertisement git clone uses", async () => {
    mockSafeFetch.mockResolvedValue(respond(200, GIT_ADVERTISEMENT));

    const result = await checkModuleSource({ git_url: "https://github.com/acme/module.git" });

    expect(result).toMatchObject({ status: "ok", url: "https://github.com/acme/module.git" });
    expect(mockSafeFetch.mock.calls[0][0]).toBe(
      "https://github.com/acme/module.git/info/refs?service=git-upload-pack",
    );
  });

  it("marks a missing or private GitHub repository not_found (GitHub answers 401)", async () => {
    mockSafeFetch.mockResolvedValue(respond(401));

    const result = await checkModuleSource({ git_url: "https://github.com/acme/gone" });

    expect(result.status).toBe("not_found");
  });

  it("marks a git_url that is a web page rather than a repository not_found", async () => {
    mockSafeFetch.mockResolvedValue(respond(200, "text/html; charset=utf-8"));

    const result = await checkModuleSource({ git_url: "https://paste.example/abc123" });

    expect(result.status).toBe("not_found");
  });

  it("probes ssh-style git URLs over https", async () => {
    mockSafeFetch.mockResolvedValue(respond(200, GIT_ADVERTISEMENT));

    await checkModuleSource({ git_url: "git@github.com:acme/module.git" });

    expect(mockSafeFetch.mock.calls[0][0]).toBe(
      "https://github.com/acme/module.git/info/refs?service=git-upload-pack",
    );
  });

  it("checks the npm package before the git repository, matching the installer's order", async () => {
    mockSafeFetch.mockResolvedValue(respond(200, "application/json"));

    const result = await checkModuleSource({
      npm_package: "@acme/threat-module@^1.2.0",
      git_url: "https://github.com/acme/module",
    });

    expect(result.status).toBe("ok");
    expect(mockSafeFetch.mock.calls[0][0]).toBe("https://registry.npmjs.org/@acme%2Fthreat-module");
  });

  it("marks a server error unreachable and a 404 not_found", async () => {
    mockSafeFetch.mockResolvedValue(respond(503));
    expect((await checkModuleSource({ tarball_url: "https://cdn.example/m.tgz" })).status).toBe("unreachable");

    mockSafeFetch.mockReset().mockResolvedValue(respond(404));
    expect((await checkModuleSource({ tarball_url: "https://cdn.example/m.tgz" })).status).toBe("not_found");
  });

  it("retries with GET when a server refuses HEAD", async () => {
    mockSafeFetch.mockResolvedValueOnce(respond(405)).mockResolvedValueOnce(respond(200));

    const result = await checkModuleSource({ tarball_url: "https://cdn.example/m.tgz" });

    expect(result.status).toBe("ok");
    expect(mockSafeFetch.mock.calls.map(([, init]) => (init as RequestInit).method)).toEqual(["HEAD", "GET"]);
  });

  it("falls back to the homepage and marks a dead host unreachable, saying the name doesn't resolve", async () => {
    mockSafeFetch.mockRejectedValue(new Error("Requests to internal addresses are not allowed"));
    mockLookup.mockRejectedValue(Object.assign(new Error("getaddrinfo ENOTFOUND"), { code: "ENOTFOUND" }));

    const result = await checkModuleSource({ homepage_url: "https://dead-tunnel.trycloudflare.com/module" });

    expect(result.status).toBe("unreachable");
    expect(result.detail).toContain("does not resolve");
  });

  it("marks a source the SSRF guard refuses unreachable", async () => {
    mockSafeFetch.mockRejectedValue(new Error("Requests to internal addresses are not allowed"));

    const result = await checkModuleSource({ git_url: "http://10.0.0.5/repo.git" });

    expect(result.status).toBe("unreachable");
    expect(result.detail).toContain("internal addresses");
  });

  it("marks a listing with no URL at all not_found without fetching", async () => {
    const result = await checkModuleSource({});

    expect(result.status).toBe("not_found");
    expect(mockSafeFetch).not.toHaveBeenCalled();
  });
});
