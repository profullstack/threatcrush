const REDIRECT_BASE = "https://threatcrush.invalid";

export function safeRedirectPath(
  value: string | null | undefined,
  fallback = "/account"
): string {
  if (!value || !value.startsWith("/")) return fallback;

  try {
    const url = new URL(value, REDIRECT_BASE);
    if (url.origin !== REDIRECT_BASE) return fallback;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return fallback;
  }
}
