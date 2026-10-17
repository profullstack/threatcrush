import { writeFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { arcSegments, demoMapData, flag, isLandAt, project, targetServer, topCountries } from "../index";
import { renderCells } from "../braille";
import { renderPng } from "../node/png";

describe("projection and land", () => {
  it("puts known places on land and the mid-Pacific in the ocean", () => {
    const at = (lat: number, lon: number) => {
      const p = project(lat, lon);
      return isLandAt(p.x, p.y);
    };
    expect(at(39.8, -98.6)).toBe(true); // Kansas
    expect(at(48.9, 2.35)).toBe(true); // Paris
    expect(at(-25, 134)).toBe(true); // Australia
    expect(at(0, -150)).toBe(false); // Pacific
    expect(at(30, -40)).toBe(false); // Atlantic
  });

  it("splits an arc that wraps the map edge instead of streaking across", () => {
    const segs = arcSegments({ lat: 35.7, lon: 139.7 }, { lat: 37.4, lon: -122 });
    expect(segs.length).toBe(2);
    for (const s of segs) for (let i = 1; i < s.length; i++) expect(Math.abs(s[i].x - s[i - 1].x)).toBeLessThan(0.5);
  });
});

describe("helpers", () => {
  it("lands an origin on its own server, else the nearest", () => {
    const servers = [
      { id: "a", name: "a", lat: 40, lon: -74 },
      { id: "b", name: "b", lat: 50, lon: 8 },
    ];
    const o = { ip: "1.2.3.4", lat: 52, lon: 4, count: 1, severity: "high" as const, lastSeen: new Date().toISOString() };
    expect(targetServer(o, servers)?.id).toBe("b");
    expect(targetServer({ ...o, serverId: "a" }, servers)?.id).toBe("a");
  });

  it("ranks countries and makes flags", () => {
    const top = topCountries(demoMapData().origins, 3);
    expect(top).toHaveLength(3);
    expect(top[0].count).toBeGreaterThanOrEqual(top[1].count);
    expect(flag("us")).toBe("🇺🇸");
    expect(flag(undefined)).toBe("🏴");
  });
});

describe("renderers", () => {
  const now = Date.parse("2026-10-17T12:00:00Z");
  const data = demoMapData(now);

  it("draws a braille map with the server and origins", () => {
    const cells = renderCells(data, 100, 30, { now });
    expect(cells).toHaveLength(30);
    expect(cells[0]).toHaveLength(100);
    const text = cells.map((r) => r.map((c) => c.ch).join("")).join("\n");
    expect(text).toContain("◆");
    expect(text).toContain("demo-server");
    expect(/[⠁-⣿]/.test(text)).toBe(true);
    if (process.env.ATTACK_MAP_DUMP) writeFileSync(`${process.env.ATTACK_MAP_DUMP}/map.txt`, text);
  });

  it("encodes a valid PNG", () => {
    const png = renderPng(data, 960, 400, { now });
    expect(png.subarray(1, 4).toString()).toBe("PNG");
    expect(png.readUInt32BE(16)).toBe(960);
    expect(png.readUInt32BE(20)).toBe(400);
    if (process.env.ATTACK_MAP_DUMP) writeFileSync(`${process.env.ATTACK_MAP_DUMP}/map.png`, png);
  });

  it("draws the bare land layer (apps/mobile/assets/attack-map-land.png)", () => {
    // Regenerate the mobile asset: ATTACK_MAP_DUMP=<dir> pnpm test, copy land.png over it.
    const png = renderPng({ servers: [], origins: [], windowMinutes: 0, generatedAt: "" }, 1080, 450, { now });
    expect(png.readUInt32BE(16)).toBe(1080);
    if (process.env.ATTACK_MAP_DUMP) writeFileSync(`${process.env.ATTACK_MAP_DUMP}/land.png`, png);
  });
});
