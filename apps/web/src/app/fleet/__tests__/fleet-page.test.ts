// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";

const auth = vi.hoisted(() => ({ value: { signedIn: false, loading: false, profile: null as unknown } }));
const replaceLocation = vi.hoisted(() => vi.fn());

vi.mock("@/lib/auth-context", () => ({ useAuth: () => auth.value }));
vi.mock("@/lib/navigate", () => ({ replaceLocation }));
vi.mock("@profullstack/fleetbar", () => ({}));

import FleetContent, { FLEET_SIGN_IN_URL } from "@/app/fleet/fleet-content";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

async function render() {
  const el = document.createElement("div");
  document.body.appendChild(el);
  const root = createRoot(el);
  await act(async () => root.render(createElement(FleetContent)));
  return { el, root };
}

afterEach(() => {
  replaceLocation.mockReset();
  document.body.innerHTML = "";
});

describe("/fleet", () => {
  it("sends a signed-out visitor to sign in, coming back to /fleet", async () => {
    auth.value = { signedIn: false, loading: false, profile: null };
    const { el } = await render();
    expect(FLEET_SIGN_IN_URL).toBe("/auth/login?next=%2Ffleet");
    expect(replaceLocation).toHaveBeenCalledWith(FLEET_SIGN_IN_URL);
    expect(el.querySelector("fleet-bar")).toBeNull();
  });

  it("waits while the session is loading", async () => {
    auth.value = { signedIn: false, loading: true, profile: null };
    await render();
    expect(replaceLocation).not.toHaveBeenCalled();
  });

  it("mounts <fleet-bar> once the fleet session cookie is set", async () => {
    auth.value = { signedIn: true, loading: false, profile: { email_verified: true } };
    const fetchMock = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const { el } = await render();
    expect(fetchMock).toHaveBeenCalledWith("/api/fleet-session", expect.objectContaining({ method: "POST" }));
    const bar = el.querySelector("fleet-bar");
    expect(bar?.getAttribute("endpoint")).toBe("/api/fleetbar");
    expect(replaceLocation).not.toHaveBeenCalled();
  });
});
