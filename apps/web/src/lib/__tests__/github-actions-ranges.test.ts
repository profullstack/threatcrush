import { afterEach, describe, expect, it, vi } from "vitest";
import { githubActionsChecker, setGitHubActionsRanges } from "../github-actions-ranges";

describe("githubActionsChecker", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("matches IPv4 and IPv6 runner ranges and nothing else", async () => {
    setGitHubActionsRanges(["172.182.192.0/18", "2a01:111:f100:1000::/62", "not-a-cidr"]);
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const isRunner = await githubActionsChecker();
    expect(isRunner("172.182.202.193")).toBe(true);
    expect(isRunner("2a01:111:f100:1001::5")).toBe(true);
    expect(isRunner("23.95.228.174")).toBe(false);
    expect(isRunner("nope")).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
