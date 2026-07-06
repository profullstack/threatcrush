import { describe, expect, it } from "vitest";
import { parsePaginationParam } from "@/lib/pagination";

describe("parsePaginationParam", () => {
  it("returns the default for missing, malformed, or fractional values", () => {
    expect(parsePaginationParam(null, 50, { min: 1, max: 200 })).toBe(50);
    expect(parsePaginationParam("abc", 50, { min: 1, max: 200 })).toBe(50);
    expect(parsePaginationParam("10.5", 50, { min: 1, max: 200 })).toBe(50);
  });

  it("clamps valid integers to the configured range", () => {
    expect(parsePaginationParam("-5", 0)).toBe(0);
    expect(parsePaginationParam("0", 50, { min: 1, max: 200 })).toBe(1);
    expect(parsePaginationParam("500", 50, { min: 1, max: 200 })).toBe(200);
  });
});

