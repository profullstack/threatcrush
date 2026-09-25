import { describe, expect, it } from "vitest";
import { parseAuthRedirectHash } from "@/lib/auth-client";

// Hashes shaped exactly like the ones GoTrue's /verify redirect produces.
describe("parseAuthRedirectHash", () => {
  it("treats a password-recovery link as recovery, never as a login session", () => {
    const hash =
      "#access_token=jwt-abc&expires_at=1790367363&expires_in=3600&refresh_token=r1&sb=&token_type=bearer&type=recovery";

    expect(parseAuthRedirectHash(hash)).toEqual({ kind: "recovery", accessToken: "jwt-abc" });
  });

  it.each([
    ["email confirmation", "#access_token=jwt-abc&refresh_token=r1&token_type=bearer&type=signup"],
    ["an OAuth sign-in with no type", "#access_token=jwt-abc&refresh_token=r1&token_type=bearer"],
  ])("treats %s as a login session", (_label, hash) => {
    expect(parseAuthRedirectHash(hash)).toEqual({ kind: "session", accessToken: "jwt-abc" });
  });

  it("surfaces GoTrue's reason for a rejected link", () => {
    const hash =
      "#error=access_denied&error_code=otp_expired&error_description=Email+link+is+invalid+or+has+expired&sb=";

    expect(parseAuthRedirectHash(hash)).toEqual({
      kind: "error",
      message: "Email link is invalid or has expired",
    });
  });

  it.each([["no hash", ""], ["an in-page anchor", "#pricing"]])("returns null for %s", (_label, hash) => {
    expect(parseAuthRedirectHash(hash)).toBeNull();
  });
});
