import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { issueSignupGrant, verifySignupGrant, SIGNUP_GRANT_TTL_SECONDS } from "@/lib/signup-grant";

const GRANT = { userId: "user-123", email: "victim@example.com" };

describe("signup grant", () => {
  beforeEach(() => {
    process.env.SIGNUP_GRANT_SECRET = "test-secret";
  });

  afterEach(() => {
    delete process.env.SIGNUP_GRANT_SECRET;
  });

  it("round-trips an issued grant", () => {
    expect(verifySignupGrant(issueSignupGrant(GRANT))).toEqual(GRANT);
  });

  it("normalizes the email", () => {
    const grant = verifySignupGrant(issueSignupGrant({ ...GRANT, email: "  Victim@Example.COM " }));
    expect(grant?.email).toBe("victim@example.com");
  });

  it("rejects a tampered payload", () => {
    const [, , signature] = issueSignupGrant(GRANT).split(".");
    const forged = Buffer.from(
      JSON.stringify({
        uid: "attacker-456",
        email: "attacker@example.com",
        exp: Math.floor(Date.now() / 1000) + SIGNUP_GRANT_TTL_SECONDS,
      }),
    ).toString("base64url");

    expect(verifySignupGrant(`v1.${forged}.${signature}`)).toBeNull();
  });

  it("rejects a grant signed with a different secret", () => {
    const token = issueSignupGrant(GRANT);
    process.env.SIGNUP_GRANT_SECRET = "a-different-secret";
    expect(verifySignupGrant(token)).toBeNull();
  });

  it("rejects an expired grant", () => {
    const token = issueSignupGrant(GRANT);
    const realNow = Date.now;
    Date.now = () => realNow() + (SIGNUP_GRANT_TTL_SECONDS + 60) * 1000;
    try {
      expect(verifySignupGrant(token)).toBeNull();
    } finally {
      Date.now = realNow;
    }
  });

  it("rejects malformed and missing tokens", () => {
    expect(verifySignupGrant(undefined)).toBeNull();
    expect(verifySignupGrant("")).toBeNull();
    expect(verifySignupGrant("not-a-token")).toBeNull();
    expect(verifySignupGrant("v2.abc.def")).toBeNull();
  });
});
