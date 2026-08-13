import type { NextResponse } from "next/server";

interface CookieReader {
  get(name: string): { value: string } | undefined;
}

type PendingCookie = string | null;

const VERIFIER_SUFFIX = "-code-verifier";
const VERIFIER_MAX_AGE_SECONDS = 10 * 60;

export function createOAuthCookieStorage(cookies: CookieReader) {
  const pending = new Map<string, PendingCookie>();

  const storage = {
    getItem(key: string): string | null {
      if (pending.has(key)) return pending.get(key) ?? null;
      return cookies.get(key)?.value ?? null;
    },
    setItem(key: string, value: string): void {
      pending.set(key, value);
    },
    removeItem(key: string): void {
      pending.set(key, null);
    },
  };

  function applyVerifierCookies(response: NextResponse, secure: boolean): void {
    for (const [name, value] of pending) {
      if (!name.endsWith(VERIFIER_SUFFIX)) continue;

      response.cookies.set({
        name,
        value: value ?? "",
        httpOnly: true,
        sameSite: "lax",
        secure,
        path: "/",
        maxAge: value === null ? 0 : VERIFIER_MAX_AGE_SECONDS,
        ...(value === null ? { expires: new Date(0) } : {}),
      });
    }
  }

  return { storage, applyVerifierCookies };
}
