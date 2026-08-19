import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const appRoot = join(__dirname, "..", "..");
const read = (p: string) => readFileSync(join(appRoot, p), "utf8");

describe("hire page", () => {
  it("states the $400 starting point without quoting a full price", () => {
    const page = read("src/app/hire/page.tsx");

    expect(page).toContain("$400");
    expect(page).toContain("scan with human input");
    expect(page).toMatch(/don&apos;t quote prices/);
  });

  it("is discoverable — canonical, sitemap, header and footer links", () => {
    expect(read("src/app/hire/page.tsx")).toContain('canonical: "/hire"');

    expect(read("src/app/sitemap.ts")).toContain('"/hire"');
    expect(read("src/components/SiteHeader.tsx")).toContain('href="/hire"');
    expect(read("src/components/SiteFooter.tsx")).toContain('href="/hire"');
  });

  it("submits inquiries to the shared contact route under the hire topic", () => {
    const form = read("src/components/HireForm.tsx");

    expect(form).toContain('"use client"');
    expect(form).toContain('fetch("/api/contact"');
    expect(form).toContain('topic: "hire"');
  });
});

describe("pricing page replacement", () => {
  it("no longer exists as a route", () => {
    expect(existsSync(join(appRoot, "src/app/pricing"))).toBe(false);
  });

  it("redirects the old URL to /hire permanently", () => {
    const config = read("next.config.ts");

    expect(config).toContain('source: "/pricing"');
    expect(config).toContain('destination: "/hire"');
    expect(config).toContain("permanent: true");
  });

  it("leaves no link pointing at the removed route", () => {
    for (const file of [
      "src/app/page.tsx",
      "src/app/about/page.tsx",
      "src/app/affiliates/page.tsx",
      "src/app/account/account-content.tsx",
      "src/app/layout.tsx",
      "src/components/SiteHeader.tsx",
      "src/components/SiteFooter.tsx",
      "src/app/sitemap.ts",
    ]) {
      expect(read(file)).not.toContain("/pricing");
    }
  });
});

describe("contact route", () => {
  it("keeps extra form fields by appending them to the persisted message", () => {
    const route = read("src/app/api/contact/route.ts");

    expect(route).toContain("messageWithExtras");
    expect(route).toContain("message: messageWithExtras(s)");
    // company and topic have their own columns, so they must not be duplicated
    // into the message body.
    expect(route).toMatch(/key !== "company" && key !== "topic"/);
  });
});
