import { describe, expect, it } from "vitest";
import {
  buildPwaCacheMessage,
  clearThreatCrushServiceWorkerCaches,
  isSecureServiceWorkerContext,
} from "../pwa-client";

describe("pwa-client", () => {
  it("allows service worker registration only in secure/local browser contexts", () => {
    expect(isSecureServiceWorkerContext({ protocol: "https:", hostname: "threatcrush.com" } as Location)).toBe(true);
    expect(isSecureServiceWorkerContext({ protocol: "http:", hostname: "localhost" } as Location)).toBe(true);
    expect(isSecureServiceWorkerContext({ protocol: "http:", hostname: "127.0.0.1" } as Location)).toBe(true);
    expect(isSecureServiceWorkerContext({ protocol: "http:", hostname: "example.com" } as Location)).toBe(false);
  });

  it("builds typed cache messages for the service worker", () => {
    expect(buildPwaCacheMessage("CLEAR_CACHES", { reason: "logout" })).toEqual({
      type: "CLEAR_CACHES",
      reason: "logout",
    });
    expect(buildPwaCacheMessage("SET_CACHE_SCOPE", { scope: "org_123" })).toEqual({
      type: "SET_CACHE_SCOPE",
      scope: "org_123",
    });
  });

  it("directly clears ThreatCrush cache namespaces when no controller is active", async () => {
    const deleted: string[] = [];
    const cacheStorage = {
      keys: async () => ["tc-static-v1", "tc-data-v2-org_123", "unrelated-cache"],
      delete: async (key: string) => {
        deleted.push(key);
        return true;
      },
    } as unknown as CacheStorage;

    await clearThreatCrushServiceWorkerCaches("logout", cacheStorage);

    expect(deleted.sort()).toEqual(["tc-data-v2-org_123", "tc-static-v1"]);
  });
});
