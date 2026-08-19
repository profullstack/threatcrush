/**
 * Serialize data for an inline `<script>` safely.
 *
 * JSON.stringify alone does not stop HTML parsing: a value containing
 * `</script>` closes the element before the JSON parser gets to see it. These
 * replacements keep the payload valid JSON while ensuring it remains text in
 * the script element.
 */
export function serializeJsonForHtml(value: unknown): string {
  const json = JSON.stringify(value) ?? "null";
  return json
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}
