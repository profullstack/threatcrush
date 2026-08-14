import { describe, it, expect } from "vitest";
import { renderSimpleMarkdown, sanitizeUrl, escapeHtml } from "@/lib/simple-markdown";

describe("escapeHtml", () => {
  it("escapes every HTML-significant character", () => {
    expect(escapeHtml(`<>&"'`)).toBe("&lt;&gt;&amp;&quot;&#39;");
  });
});

describe("sanitizeUrl", () => {
  it("keeps http, https and mailto", () => {
    expect(sanitizeUrl("https://example.com/x")).toBe("https://example.com/x");
    expect(sanitizeUrl("http://example.com")).toBe("http://example.com");
    expect(sanitizeUrl("mailto:a@example.com")).toBe("mailto:a@example.com");
  });

  it("keeps same-page and root-relative links", () => {
    expect(sanitizeUrl("/docs")).toBe("/docs");
    expect(sanitizeUrl("#anchor")).toBe("#anchor");
  });

  it("drops script-bearing protocols", () => {
    expect(sanitizeUrl("javascript:alert(1)")).toBe("#");
    expect(sanitizeUrl("  JavaScript:alert(1)")).toBe("#");
    expect(sanitizeUrl("data:text/html;base64,PHNjcmlwdD4=")).toBe("#");
    expect(sanitizeUrl("vbscript:msgbox(1)")).toBe("#");
  });

  it("drops protocol-relative URLs", () => {
    expect(sanitizeUrl("//attacker.example")).toBe("#");
  });
});

describe("renderSimpleMarkdown", () => {
  // TC-04: headings interpolated raw line content into the tag body.
  it("escapes markup in headings", () => {
    const html = renderSimpleMarkdown("# <img src=x onerror=alert(1)>");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("escapes markup in paragraphs, lists and bold text", () => {
    for (const source of [
      "<script>alert(1)</script>",
      "- <script>alert(1)</script>",
      "**<script>alert(1)</script>**",
    ]) {
      const html = renderSimpleMarkdown(source);
      expect(html).not.toContain("<script>");
      expect(html).toContain("&lt;script&gt;");
    }
  });

  // TC-39: [text](javascript:...) produced a working script link.
  it("neutralizes javascript: links", () => {
    const html = renderSimpleMarkdown("[click me](javascript:alert(document.cookie))");
    expect(html).not.toContain("javascript:");
    expect(html).toContain('href="#"');
  });

  it("does not let a link URL break out of the href attribute", () => {
    const html = renderSimpleMarkdown('[x](https://a.example" onmouseover="alert(1))');
    expect(html).not.toContain('onmouseover="alert(1)"');
    expect(html).not.toContain('" onmouseover');
  });

  it("still renders the intended markup", () => {
    expect(renderSimpleMarkdown("# Title")).toContain("<h1");
    expect(renderSimpleMarkdown("**bold**")).toContain("<strong");
    expect(renderSimpleMarkdown("`code`")).toContain("<code");
    expect(renderSimpleMarkdown("- item")).toContain("<li");
    expect(renderSimpleMarkdown("[docs](https://example.com)")).toContain(
      'href="https://example.com"',
    );
  });

  it("marks external links noopener noreferrer", () => {
    const html = renderSimpleMarkdown("[docs](https://example.com)");
    expect(html).toContain('rel="noopener noreferrer"');
  });
});
