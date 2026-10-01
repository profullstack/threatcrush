import sanitize from "sanitize-html";

// Blog post HTML is sanitized with sanitize-html (htmlparser2, no DOM) rather
// than DOMPurify: isomorphic-dompurify needs jsdom on the server, and jsdom's
// css-tree loads `../data/patch.json` with a relative require that Bun cannot
// resolve from Next's bundled externals, so every blog page 500'd under Bun.
// The rules below reproduce the DOMPurify configuration this replaced.

const ALLOWED_TAGS = [
  "h1", "h2", "h3", "h4", "h5", "h6",
  "p", "br", "hr",
  "strong", "em", "b", "i", "u", "s", "code", "pre", "blockquote",
  "ul", "ol", "li",
  "a", "img", "figure", "figcaption",
  "table", "thead", "tbody", "tr", "th", "td",
  "span", "div",
];

const ALLOWED_ATTR = ["href", "src", "alt", "title", "target", "rel", "class", "id", "loading"];

// DOMPurify's ALLOWED_URI_REGEXP: absolute http(s)/mailto, root-relative, or a
// fragment. Anything else (javascript:, relative paths, unknown schemes) loses
// the attribute, as it did before.
const ALLOWED_URI = /^(?:(?:https?|mailto):|\/|#)/i;
// DOMPurify strips whitespace and control characters before testing a URI.
// Built from a string: a literal U+2028/U+2029 range breaks some TS strippers.
const URI_WHITESPACE = new RegExp("[\\u0000-\\u0020\\u00A0\\u1680\\u180E\\u2000-\\u2029\\u205F\\u3000]", "g");

// Elements whose contents DOMPurify drops along with the element itself
// (its FORBID_CONTENTS default); other disallowed elements keep their text.
const DROP_CONTENTS = [
  "script", "style", "iframe", "noscript", "noembed", "noframes", "template",
  "title", "xmp", "plaintext", "svg", "math", "audio", "video", "head",
];

function uriAllowed(tag: string, value: string): boolean {
  const v = value.replace(URI_WHITESPACE, "");
  if (!v) return true;
  if (ALLOWED_URI.test(v)) return true;
  // DOMPurify also keeps data: URIs on images.
  return tag === "img" && v.toLowerCase().startsWith("data:");
}

const OPTIONS: sanitize.IOptions = {
  allowedTags: ALLOWED_TAGS,
  // DOMPurify also keeps data-* attributes by default (ALLOW_DATA_ATTR).
  allowedAttributes: { "*": [...ALLOWED_ATTR, "data-*"] },
  // URI checking is done in transformTags below, with DOMPurify's rule.
  allowedSchemes: ["http", "https", "mailto", "data"],
  allowedSchemesByTag: {},
  allowProtocolRelative: true,
  nonTextTags: DROP_CONTENTS,
  disallowedTagsMode: "discard",
  transformTags: {
    "*": (tagName, attribs) => {
      const out = { ...attribs };
      // DOMPurify 3.4 removed rel and target from every link even though both
      // were listed (what threatcrush.com serves today); keep the output the same.
      delete out.rel;
      delete out.target;
      for (const name of ["href", "src"]) {
        if (name in out && !uriAllowed(tagName, out[name])) delete out[name];
      }
      return { tagName, attribs: out };
    },
  },
};

export function sanitizeBlogHtml(html: string): string {
  return sanitize(html, OPTIONS);
}
