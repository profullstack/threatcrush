import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";
import { GET } from "../route";

function get(url: string) {
  return GET(new NextRequest(url));
}

describe("GET /api", () => {
  it("sends a GitHub App setup redirect to the confirmation page", async () => {
    const response = await get(
      "https://threatcrush.com/api?code=9b2c20dd5e3b8e7e0702&installation_id=155501023&setup_action=install"
    );

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") || "");
    expect(location.pathname).toBe("/github/installed");
    expect(location.searchParams.get("installation_id")).toBe("155501023");
    expect(location.searchParams.get("setup_action")).toBe("install");
  });

  it("does not forward the OAuth code to the browser", async () => {
    const response = await get(
      "https://threatcrush.com/api?code=9b2c20dd5e3b8e7e0702&installation_id=155501023&setup_action=install"
    );

    expect(response.headers.get("location")).not.toContain("9b2c20dd5e3b8e7e0702");
    expect(response.headers.get("location")).not.toContain("code=");
  });

  it("keeps setup_action=request distinct, since nothing is installed yet", async () => {
    const response = await get(
      "https://threatcrush.com/api?installation_id=155501023&setup_action=request"
    );

    const location = new URL(response.headers.get("location") || "");
    expect(location.searchParams.get("setup_action")).toBe("request");
  });

  it("drops an installation_id that is not numeric and falls back on a bad action", async () => {
    const response = await get(
      "https://threatcrush.com/api?installation_id=%3Cscript%3E&setup_action=wat"
    );

    const location = new URL(response.headers.get("location") || "");
    expect(location.searchParams.has("installation_id")).toBe(false);
    expect(location.searchParams.get("setup_action")).toBe("install");
  });

  it("redirects on installation_id alone, without setup_action", async () => {
    const response = await get("https://threatcrush.com/api?installation_id=155501023");

    expect(response.status).toBe(302);
    expect(new URL(response.headers.get("location") || "").pathname).toBe("/github/installed");
  });

  it("serves an API index when there are no setup parameters", async () => {
    const response = await get("https://threatcrush.com/api");

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.name).toBe("ThreatCrush API");
    expect(body.endpoints.health).toBe("/api/health");
  });
});
