import { describe, expect, it } from "vitest";
import { JSDOM } from "jsdom";
import { sanitizeBlogHtml } from "@/lib/sanitize-blog-html";
import realCases from "./fixtures/blog-sanitize-real.json";

// Compare parsed DOMs: sanitize-html and DOMPurify serialize a few things
// differently (`<br>` vs `<br />`, attribute quoting) without changing the page.
const dom = (html: string) =>
  new JSDOM(`<body>${html.trim()}</body>`).window.document.body.innerHTML.trim();

describe("sanitizeBlogHtml", () => {
  describe("matches the DOMPurify output it replaced, on real blog content", () => {
    // Inputs are excerpts of live threatcrush.com posts; expected values are what
    // isomorphic-dompurify 3.12 (DOMPurify 3.4.2) produced with the old options.
    for (const [name, c] of Object.entries(realCases as Record<string, { input: string; expected: string }>)) {
      it(name, () => {
        expect(dom(sanitizeBlogHtml(c.input))).toBe(dom(c.expected));
      });
    }
  });

  it("removes script, style and iframe elements together with their contents", () => {
    const out = sanitizeBlogHtml(
      '<p>a</p><script>alert(1)</script><style>p{}</style><iframe src="https://x">t</iframe><p>b</p>',
    );
    expect(dom(out)).toBe("<p>a</p><p>b</p>");
  });

  it("removes event handler and style attributes", () => {
    const out = sanitizeBlogHtml(
      '<p onclick="alert(1)" style="color:red">x</p><img src="/a.png" onerror="alert(1)" alt="a">',
    );
    expect(out).not.toMatch(/onclick|onerror|style=/);
    expect(dom(out)).toBe('<p>x</p><img src="/a.png" alt="a">');
  });

  it("drops javascript:, unknown-scheme and relative URLs but keeps safe ones", () => {
    const out = sanitizeBlogHtml(
      [
        '<a href="javascript:alert(1)">1</a>',
        '<a href=" jav&#x09;ascript:alert(1)">2</a>',
        '<a href="vbscript:x">3</a>',
        '<a href="page.html">4</a>',
        '<a href="https://threatcrush.com/x">5</a>',
        '<a href="/blog">6</a>',
        '<a href="#top">7</a>',
        '<a href="mailto:a@b.c">8</a>',
      ].join(""),
    );
    expect(dom(out)).toBe(
      "<a>1</a><a>2</a><a>3</a><a>4</a>" +
        '<a href="https://threatcrush.com/x">5</a><a href="/blog">6</a><a href="#top">7</a><a href="mailto:a@b.c">8</a>',
    );
  });

  it("keeps data: images but not data: links", () => {
    const out = sanitizeBlogHtml('<img src="data:image/png;base64,AAAA"><a href="data:text/html,x">d</a>');
    expect(dom(out)).toBe('<img src="data:image/png;base64,AAAA"><a>d</a>');
  });

  it("keeps text of unknown elements such as form controls and aside", () => {
    expect(dom(sanitizeBlogHtml("<aside><form><b>kept</b></form></aside>"))).toBe("<b>kept</b>");
  });
});
