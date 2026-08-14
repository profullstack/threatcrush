/**
 * A deliberately tiny Markdown subset (headers, bold, inline code, links,
 * bullets) used for module `long_description`, which is author-supplied and
 * therefore untrusted.
 *
 * TC-04 / TC-39: the previous version interpolated raw line content into HTML
 * strings and handed the result to dangerouslySetInnerHTML, so a module author
 * could inject arbitrary markup, and `[x](javascript:...)` produced a working
 * script link.
 *
 * The order here is what makes it safe: escape the whole line FIRST, then apply
 * the markdown rules to the escaped text. After escaping there is no `<`, `>`
 * or quote left for an attacker to build a tag or break out of an attribute
 * with, so every tag in the output is one this module wrote.
 */

const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export function escapeHtml(input: string): string {
  return input.replace(/[&<>"']/g, (char) => HTML_ESCAPES[char]);
}

/**
 * Only http/https/mailto links survive. Everything else — javascript:, data:,
 * vbscript:, and protocol-relative or unparseable junk — collapses to "#".
 */
export function sanitizeUrl(rawUrl: string): string {
  // The URL arrives HTML-escaped; decode the entities the escaper introduced so
  // the protocol check sees the same string the browser eventually would.
  const candidate = rawUrl
    .replace(/&amp;/g, "&")
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .trim();

  // Relative links are fine and have no protocol to check.
  if (/^[/#?]/.test(candidate) && !candidate.startsWith("//")) return escapeHtml(candidate);

  try {
    const { protocol } = new URL(candidate);
    if (protocol === "http:" || protocol === "https:" || protocol === "mailto:") {
      return escapeHtml(candidate);
    }
  } catch {
    // Not an absolute URL — fall through.
  }
  return "#";
}

export function renderSimpleMarkdown(content: string): string {
  return content
    .split("\n")
    .map((rawLine) => {
      const line = escapeHtml(rawLine);

      if (line.startsWith("### ")) {
        return `<h3 class="text-lg font-bold text-white mt-6 mb-2">${line.slice(4)}</h3>`;
      }
      if (line.startsWith("## ")) {
        return `<h2 class="text-xl font-bold text-white mt-8 mb-3">${line.slice(3)}</h2>`;
      }
      if (line.startsWith("# ")) {
        return `<h1 class="text-2xl font-bold text-white mt-8 mb-4">${line.slice(2)}</h1>`;
      }

      // Inline code
      let processed = line.replace(
        /`([^`]+)`/g,
        '<code class="bg-tc-darker px-1.5 py-0.5 rounded text-tc-green text-xs font-mono">$1</code>',
      );
      // Bold
      processed = processed.replace(
        /\*\*([^*]+)\*\*/g,
        '<strong class="text-white font-bold">$1</strong>',
      );
      // Links
      processed = processed.replace(
        /\[([^\]]+)\]\(([^)]+)\)/g,
        (_match, text: string, url: string) =>
          `<a href="${sanitizeUrl(url)}" target="_blank" rel="noopener noreferrer" class="text-tc-green hover:underline">${text}</a>`,
      );

      if (processed.startsWith("- ") || processed.startsWith("* ")) {
        return `<li class="ml-4 text-tc-text-dim text-sm leading-relaxed list-disc">${processed.slice(2)}</li>`;
      }
      if (!processed.trim()) return "<br/>";
      return `<p class="text-tc-text-dim text-sm leading-relaxed">${processed}</p>`;
    })
    .join("\n");
}
