import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock server-only to prevent import errors in test
vi.mock("server-only", () => ({}));

// Mock @supabase/supabase-js before importing
vi.mock("@supabase/supabase-js", () => ({
  createClient: vi.fn().mockReturnValue({ from: vi.fn() }),
}));

import { slugify, getSupabaseClient, getSupabaseAdmin } from "@/lib/supabase";
import { createClient } from "@supabase/supabase-js";

describe("slugify", () => {
  it("converts simple names to valid slugs", () => {
    expect(slugify("Network Monitor")).toBe("network-monitor");
  });

  it("converts camelCase to slug", () => {
    expect(slugify("myModule")).toBe("mymodule");
  });

  it("handles special characters", () => {
    expect(slugify("hello@world! #2024")).toBe("hello-world-2024");
  });

  it("handles multiple consecutive special chars", () => {
    expect(slugify("foo---bar___baz")).toBe("foo-bar-baz");
  });

  it("trims leading/trailing dashes", () => {
    expect(slugify("--hello--")).toBe("hello");
  });

  it("handles empty string", () => {
    expect(slugify("")).toBe("");
  });

  it("handles string with only special chars", () => {
    expect(slugify("@#$%")).toBe("");
  });

  it("preserves numbers", () => {
    expect(slugify("module-v2.0")).toBe("module-v2-0");
  });
});

describe("getSupabaseClient", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns a Supabase client instance", () => {
    const client = getSupabaseClient();
    expect(client).toBeDefined();
    expect(createClient).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String)
    );
  });
});

describe("getSupabaseAdmin", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns a Supabase admin client instance", () => {
    const client = getSupabaseAdmin();
    expect(client).toBeDefined();
    expect(createClient).toHaveBeenCalled();
  });
});
