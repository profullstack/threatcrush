"use client";

import { useEffect, useState } from "react";
import { safeRedirectPath } from "@/lib/safe-redirect";

/**
 * The validated `?next=` path for auth pages.
 *
 * Read after mount, never during render: the server renders without `window`,
 * and React hydration keeps the server's attribute values instead of patching
 * mismatches. A `useMemo` that returned "/account" on the server baked that
 * into every `href` (Sign in with CoinPay, GitHub, Create account), so OAuth
 * logins dropped `next` while the password form, which reads it in JS, worked.
 */
export function useNextPath(fallback = "/account"): string {
  const [nextPath, setNextPath] = useState(fallback);
  useEffect(() => {
    setNextPath(safeRedirectPath(new URLSearchParams(window.location.search).get("next")));
  }, []);
  return nextPath;
}
