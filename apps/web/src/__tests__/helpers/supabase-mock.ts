import { vi } from "vitest";

/**
 * Creates a chainable Supabase query builder mock.
 * Call with the final data/error/count to return.
 */
export function createQueryMock(result: {
  data?: unknown;
  error?: { message: string } | null;
  count?: number | null;
} = { data: null, error: null, count: null }) {
  const mock: Record<string, ReturnType<typeof vi.fn>> = {};

  const chainable = () =>
    new Proxy(
      {},
      {
        get(_target, prop: string) {
          if (prop === "then") return undefined; // not a promise itself
          if (!mock[prop]) {
            mock[prop] = vi.fn().mockReturnValue(chainable());
          }
          // Terminal methods return the result
          if (["single", "maybeSingle"].includes(prop)) {
            mock[prop] = vi.fn().mockResolvedValue(result);
            return mock[prop];
          }
          // range returns self but the await resolves
          if (prop === "range") {
            mock[prop] = vi.fn().mockReturnValue({
              then: (resolve: (v: unknown) => void) => resolve(result),
              ...chainable(),
            });
            return mock[prop];
          }
          return mock[prop];
        },
      }
    );

  return chainable();
}

/**
 * Creates a mock Supabase client with configurable table responses.
 */
export function createSupabaseMock(tableResponses: Record<string, unknown> = {}) {
  const fromMock = vi.fn((table: string) => {
    if (tableResponses[table]) return tableResponses[table];
    return createQueryMock();
  });

  return {
    from: fromMock,
    storage: {
      from: vi.fn().mockReturnValue({
        upload: vi.fn().mockResolvedValue({ error: null }),
        getPublicUrl: vi.fn().mockReturnValue({ data: { publicUrl: "https://test.supabase.co/storage/test.png" } }),
      }),
    },
  };
}

/** Standard test module fixture */
export const TEST_MODULE = {
  id: "mod-001",
  name: "test-scanner",
  slug: "test-scanner",
  display_name: "Test Scanner",
  description: "A test security module",
  long_description: "Detailed description of the test module",
  author_name: "tester",
  author_email: "test@example.com",
  homepage_url: "https://example.com",
  git_url: "https://github.com/test/scanner",
  logo_url: null,
  banner_url: null,
  screenshot_url: null,
  license: "MIT",
  pricing_type: "free",
  price_usd: null,
  category: "security",
  tags: ["scanner", "test"],
  keywords: "scanner,test",
  version: "1.0.0",
  min_threatcrush_version: ">=0.1.0",
  os_support: ["linux"],
  capabilities: [],
  downloads: 42,
  rating_avg: 4.5,
  rating_count: 10,
  published: true,
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-06-01T00:00:00Z",
};

/** Standard test review fixture */
export const TEST_REVIEW = {
  id: "rev-001",
  module_id: "mod-001",
  user_email: "reviewer@example.com",
  rating: 5,
  title: "Great module",
  body: "Works perfectly",
  created_at: "2025-03-01T00:00:00Z",
};
