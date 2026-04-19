import { describe, expect, it } from "vitest";

/**
 * Contract-driven examples for module publishers + QA.
 *
 * These are not runtime integration tests. They are living examples of the
 * request/response and manifest shapes the platform expects.
 */

describe("module contract examples", () => {
  it("example module manifest shape", () => {
    const manifest = {
      module: {
        name: "example-alert-module",
        version: "0.1.0",
        description: "Example ThreatCrush module that reacts to events and emits alerts",
        author: "Your Name",
        license: "MIT",
        homepage: "https://example.com/modules/example-alert-module",
      },
      pricing: {
        type: "free",
      },
      requirements: {
        threatcrush: ">=0.1.0",
        os: ["linux"],
        capabilities: [],
      },
      defaults: {
        enabled: true,
        watch_event_types: ["network:connection", "log:auth"],
        severity_threshold: "medium",
      },
    };

    expect(manifest).toEqual(
      expect.objectContaining({
        module: expect.objectContaining({
          name: expect.any(String),
          version: expect.any(String),
          description: expect.any(String),
          author: expect.any(String),
          license: expect.any(String),
          homepage: expect.any(String),
        }),
        pricing: expect.objectContaining({
          type: expect.stringMatching(/^(free|paid|freemium)$/),
        }),
        requirements: expect.objectContaining({
          threatcrush: expect.any(String),
          os: expect.any(Array),
          capabilities: expect.any(Array),
        }),
      })
    );
  });

  it("example publish payload shape", () => {
    const payload = {
      name: "example-alert-module",
      display_name: "Example Alert Module",
      description: "Example ThreatCrush module that reacts to events and emits alerts",
      category: "security",
      tags: ["security", "alerts"],
      version: "0.1.0",
      license: "MIT",
      author_name: "Your Name",
      author_email: "you@example.com",
      logo_url: "https://example.com/logo.png",
      homepage_url: "https://example.com/modules/example-alert-module",
      git_url: "https://github.com/example/example-alert-module",
      pricing_type: "free",
      price_usd: null,
    };

    expect(payload).toEqual(
      expect.objectContaining({
        name: expect.any(String),
        display_name: expect.any(String),
        description: expect.any(String),
        category: expect.any(String),
        tags: expect.any(Array),
        version: expect.any(String),
        license: expect.any(String),
        author_name: expect.any(String),
        author_email: expect.stringContaining("@"),
        pricing_type: expect.stringMatching(/^(free|paid|freemium)$/),
      })
    );
  });

  it("example successful publish response shape", () => {
    const response = {
      module: {
        id: "mod_123",
        name: "example-alert-module",
        slug: "example-alert-module",
        display_name: "Example Alert Module",
        author_email: "you@example.com",
        published: true,
        pricing_type: "free",
        version: "0.1.0",
      },
    };

    expect(response).toEqual(
      expect.objectContaining({
        module: expect.objectContaining({
          id: expect.any(String),
          name: expect.any(String),
          slug: expect.any(String),
          author_email: expect.any(String),
          pricing_type: expect.any(String),
          version: expect.any(String),
        }),
      })
    );
  });

  it("example auth failure response shape", () => {
    const response = {
      error: "You must be logged in to publish modules.",
    };

    expect(response).toEqual({
      error: expect.any(String),
    });
  });

  it("example author-email mismatch response shape", () => {
    const response = {
      error: "Author email must match your logged-in account.",
    };

    expect(response).toEqual({
      error: expect.any(String),
    });
  });
});
