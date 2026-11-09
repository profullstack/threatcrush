// @vitest-environment jsdom
import { createElement } from "react";
import { act } from "react";
import { renderToString } from "react-dom/server";
import { hydrateRoot } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";
import { useNextPath } from "../use-next-path";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function CoinpayLink() {
  const nextPath = useNextPath();
  return createElement("a", { href: `/api/v1/coinpay/oauth/start?next=${encodeURIComponent(nextPath)}` }, "CoinPay");
}

describe("useNextPath", () => {
  afterEach(() => {
    window.history.replaceState(null, "", "/");
    document.body.innerHTML = "";
  });

  it("server-renders the fallback, then the hydrated href carries ?next=", async () => {
    window.history.replaceState(null, "", "/auth/login?next=%2Fic%2F048352");
    const html = renderToString(createElement(CoinpayLink));
    expect(html).toContain("next=%2Faccount");

    const container = document.createElement("div");
    container.innerHTML = html;
    document.body.appendChild(container);
    await act(async () => {
      hydrateRoot(container, createElement(CoinpayLink));
    });

    expect(container.querySelector("a")?.getAttribute("href")).toBe(
      "/api/v1/coinpay/oauth/start?next=%2Fic%2F048352",
    );
  });

  it("rejects an off-site next", async () => {
    window.history.replaceState(null, "", "/auth/login?next=%2F%2Fevil.example");
    const container = document.createElement("div");
    container.innerHTML = renderToString(createElement(CoinpayLink));
    document.body.appendChild(container);
    await act(async () => {
      hydrateRoot(container, createElement(CoinpayLink));
    });
    expect(container.querySelector("a")?.getAttribute("href")).toBe("/api/v1/coinpay/oauth/start?next=%2Faccount");
  });
});
