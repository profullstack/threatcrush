import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => { throw new Error("no db in tests"); } }));
const { closestSlug, editDistance, fixBlogLinks } = await import("@/lib/blog");

const SLUGS = new Set(["automation-in-cyber-security", "incident-response-automation", "siem-and-soc"]);

describe("blog link repair", () => {
  it("finds the slug a mistyped link meant", () => {
    expect(editDistance("automation-in-cy-security", "automation-in-cyber-security")).toBe(3);
    expect(closestSlug("automation-in-cy-security", SLUGS)).toBe("automation-in-cyber-security");
    expect(closestSlug("siem-and-soc", SLUGS)).toBe("siem-and-soc");
    expect(closestSlug("quantum-firewall-guide", SLUGS)).toBeNull();
  });

  it("rewrites the bad link found live, relative and absolute, keeping anchors", () => {
    const html =
      '<a href="/blog/automation-in-cy-security">x</a> <a href="https://threatcrush.com/blog/automation-in-cy-security#top">y</a>';
    expect(fixBlogLinks(html, SLUGS)).toBe(
      '<a href="/blog/automation-in-cyber-security">x</a> <a href="https://threatcrush.com/blog/automation-in-cyber-security#top">y</a>',
    );
  });

  it("points a link to a post that never existed at the index; leaves good and external links alone", () => {
    const html =
      '<a href="/blog/quantum-firewall-guide">q</a><a href="/blog/siem-and-soc">ok</a><a href="https://other.example/blog/nope">e</a>';
    expect(fixBlogLinks(html, SLUGS)).toBe(
      '<a href="/blog">q</a><a href="/blog/siem-and-soc">ok</a><a href="https://other.example/blog/nope">e</a>',
    );
    expect(fixBlogLinks(html, new Set())).toBe(html);
  });
});
