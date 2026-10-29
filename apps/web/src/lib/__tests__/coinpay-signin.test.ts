import { describe, expect, it } from "vitest";
import {
  accountForCoinpayLogin,
  beginCoinpay,
  isPlaceholderEmail,
  linkIdentity,
  openPending,
  sealPending,
  type PendingSignIn,
} from "@/lib/coinpay-signin";
import { fakeAdmin } from "@/__tests__/helpers/coinpay-fake-admin";

const SECRET = "client-secret";
const config = { clientId: "cp_tc", clientSecret: SECRET, appUrl: "https://threatcrush.com", redirectUri: "https://threatcrush.com/api/v1/coinpay/oauth/callback" };

describe("Sign in with CoinPay (threatcrush)", () => {
  it("start sends S256, state and nonce to CoinPay's authorize endpoint with the exact redirect", () => {
    const { url, cookie } = beginCoinpay(config, { mode: "login", next: "/cli/login?request=x" });
    const u = new URL(url);
    expect(u.origin + u.pathname).toBe("https://coinpayportal.com/api/oauth/authorize");
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("redirect_uri")).toBe(config.redirectUri);
    expect(u.searchParams.get("scope")).toBe("openid profile email");
    const pending = openPending(cookie, SECRET)!;
    expect(pending.state).toBe(u.searchParams.get("state"));
    expect(pending.nonce).toBe(u.searchParams.get("nonce"));
    expect(pending.next).toBe("/cli/login?request=x");
  });

  it("a forged, re-signed or expired pending cookie is refused", () => {
    const pending: PendingSignIn = { mode: "link", state: "s", nonce: "n", verifier: "v", next: "/account", userId: "victim", exp: Date.now() + 60_000 };
    const sealed = sealPending(pending, SECRET);
    expect(openPending(sealed, SECRET)?.userId).toBe("victim");
    expect(openPending(sealed, "other-secret")).toBeNull();
    const [payload, sig] = sealed.split(".");
    const tampered = Buffer.from(JSON.stringify({ ...pending, userId: "attacker" })).toString("base64url");
    expect(openPending(`${tampered}.${sig}`, SECRET)).toBeNull();
    expect(payload).toBeTruthy();
    expect(openPending(sealPending({ ...pending, exp: Date.now() - 1 }, SECRET), SECRET)).toBeNull();
    expect(openPending(sealPending({ ...pending, userId: null }, SECRET), SECRET)).toBeNull();
  });

  it("a CoinPay login whose email equals an existing user's email gets a NEW account, not that user's", async () => {
    const admin = fakeAdmin({ users: [{ id: "victim", email: "victim@example.com" }] });
    const account = await accountForCoinpayLogin(admin as never, { sub: "cp_sub_1", email: "victim@example.com", name: "Eve" }, async (id, email) => {
      admin.profiles.push({ id, email });
    });
    expect(account?.created).toBe(true);
    expect(account?.userId).not.toBe("victim");
    expect(isPlaceholderEmail(account?.authEmail)).toBe(true);
    expect(admin.identities).toEqual([{ sub: "cp_sub_1", user_id: account!.userId, email: "victim@example.com", name: "Eve", last_login_at: expect.any(String) }]);
    expect(admin.profiles[0]).toMatchObject({ id: account!.userId });
    expect((admin.profiles[0] as { email: string }).email).not.toBe("victim@example.com");
  });

  it("a second CoinPay login with the same sub signs into the bound account", async () => {
    const admin = fakeAdmin({ users: [{ id: "alice", email: "alice@example.com" }], identities: [{ sub: "cp_a", user_id: "alice", email: null, name: null }] });
    const account = await accountForCoinpayLogin(admin as never, { sub: "cp_a", email: "other@example.com", name: "A" }, async () => {});
    expect(account).toEqual({ userId: "alice", authEmail: "alice@example.com", created: false });
  });

  it("linking binds the sub to the signed-in user only, and never steals a bound sub", async () => {
    const admin = fakeAdmin({ identities: [{ sub: "cp_taken", user_id: "bob", email: null, name: null }] });
    expect(await linkIdentity(admin as never, "alice", { sub: "cp_taken", email: null, name: null })).toBe("sub_taken");
    expect(await linkIdentity(admin as never, "alice", { sub: "cp_new", email: "a@x.io", name: null })).toBe("linked");
    expect(await linkIdentity(admin as never, "alice", { sub: "cp_new", email: null, name: null })).toBe("already_linked");
    expect(await linkIdentity(admin as never, "alice", { sub: "cp_third", email: null, name: null })).toBe("user_has_other");
    expect(admin.identities.find((r) => r.sub === "cp_taken")?.user_id).toBe("bob");
  });
});
