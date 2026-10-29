import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const appRoot = join(__dirname, "..", "..");
const read = (p: string) => readFileSync(join(appRoot, p), "utf8");

describe("hire page", () => {
  it("sells the $400 scan outright and quotes anything bigger", () => {
    const page = read("src/app/hire/page.tsx");

    expect(page).toContain("SCAN_PRICE_USD");
    expect(page).toContain("scan with human input");
    expect(page).toContain("CheckoutPanel");
  });

  it("is discoverable — canonical, sitemap, header and footer links", () => {
    expect(read("src/app/hire/page.tsx")).toContain('canonical: "/hire"');

    expect(read("src/app/sitemap.ts")).toContain('"/hire"');
    expect(read("src/components/SiteHeader.tsx")).toContain('href="/hire"');
    expect(read("src/components/SiteFooter.tsx")).toContain('href: "/hire"');
  });

  it("renders the shared contact form, minted per render, under the hire topic", () => {
    const page = read("src/app/hire/page.tsx");
    const form = read("src/components/HireForm.tsx");
    const contact = read("src/lib/contact.ts");

    expect(page).toContain("await contact.props()");
    expect(page).toContain('export const dynamic = "force-dynamic"');
    expect(form).toContain('from "@profullstack/contact-form/react"');
    expect(contact).toContain('{ name: "topic", type: "hidden", value: "hire" }');
    // A visible honeypot drops the real people who fill it in.
    expect(read("src/app/globals.css")).toMatch(/\.cf-hp\s*\{[^}]*left:\s*-9999px/);
  });
});

describe("pricing page", () => {
  it("is a real route again, not a redirect to /hire", () => {
    expect(existsSync(join(appRoot, "src/app/pricing/page.tsx"))).toBe(true);
    expect(read("next.config.ts")).not.toContain('source: "/pricing"');
  });

  it("sells every product through the shared checkout, the $400 scan included", () => {
    const page = read("src/app/pricing/page.tsx");
    expect(page).toContain("CheckoutPanel");
    expect(page).toContain("reputation-pro");
    expect(page).toContain("link-watch");
    expect(page).toContain("SCAN_PRICE_USD");
    expect(page).toContain('canonical: "/pricing"');
  });

  it("is discoverable from the sitemap, header and footer", () => {
    expect(read("src/app/sitemap.ts")).toContain('"/pricing"');
    expect(read("src/components/SiteHeader.tsx")).toContain('href="/pricing"');
    expect(read("src/components/SiteFooter.tsx")).toContain('href: "/pricing"');
  });
});

describe("contact route", () => {
  it("keeps extra form fields by appending them to the persisted message", () => {
    const contact = read("src/lib/contact.ts");

    expect(contact).toContain("message: messageWithExtras(s)");
    expect(read("src/app/api/contact/route.ts")).toContain("contact.POST");
  });
});
