import { describe, expect, it } from "vitest";
import { installUserAgent, isOurHost, USER_AGENT } from "../user-agent.js";
import { PKG_VERSION } from "../version.js";

function fakeFetch() {
  const seen: { url: string; ua: string | null }[] = [];
  const target = {
    fetch: (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      seen.push({ url, ua: new Headers(init?.headers).get("user-agent") });
      return new Response("ok");
    }) as typeof fetch,
  };
  return { target, seen };
}

describe("user agent", () => {
  it("names the CLI and its version in a form the nightly report parses", () => {
    expect(USER_AGENT.startsWith(`threatcrush/${PKG_VERSION} `)).toBe(true);
  });

  it("only matches our own hosts", () => {
    expect(isOurHost("https://threatcrush.com/api/ingest", "https://threatcrush.com")).toBe(true);
    expect(isOurHost("https://supabase.threatcrush.com/rest/v1/x", "https://threatcrush.com")).toBe(true);
    expect(isOurHost("http://localhost:3000/api/ingest", "http://localhost:3000")).toBe(true);
    expect(isOurHost("https://evilthreatcrush.com/", "https://threatcrush.com")).toBe(false);
    expect(isOurHost("https://feodotracker.abuse.ch/x", "https://threatcrush.com")).toBe(false);
    expect(isOurHost("not a url", "https://threatcrush.com")).toBe(false);
  });

  it("adds the agent to our API, keeps other headers, leaves third parties and explicit agents alone", async () => {
    const { target, seen } = fakeFetch();
    installUserAgent(target);
    installUserAgent(target); // idempotent: no double wrap
    await target.fetch("https://threatcrush.com/api/ingest", { method: "POST", headers: { authorization: "Bearer x" } });
    await target.fetch(new URL("https://threatcrush.com/api/auth/me"));
    await target.fetch("https://discord.com/api/webhooks/1");
    await target.fetch("https://threatcrush.com/api/x", { headers: { "User-Agent": "custom" } });
    expect(seen.map((s) => s.ua)).toEqual([USER_AGENT, USER_AGENT, null, "custom"]);
  });
});
