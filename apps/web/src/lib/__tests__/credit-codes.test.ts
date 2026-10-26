import { describe, expect, it } from "vitest";
import { Credits, memoryStore as creditMemory } from "@profullstack/redeem-credits";
import { Affiliates, memoryStore as affMemory } from "@profullstack/affiliates";
import {
  INVITE_BONUS_CREDITS,
  INVITE_MIN_ACCOUNT_AGE_DAYS,
  applyGrant,
  acceptInvite,
  canonicalEmail,
  cleanInviteCode,
  createInvite,
  inviteOverview,
  mintCreditCode,
  onSignedIn,
  redeemCreditCode,
  revokeInvite,
  settleInviteBonus,
  type AuthInfo,
  type CreditDeps,
} from "@/lib/credit-codes";

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse("2026-10-26T12:00:00Z");

type Deposit = { user_id: string; amount_usd: number; status: string; grant_source: string | null };

/**
 * Just enough of supabase-js for lib/credit-codes: the grant_code_credits RPC
 * (credit_deposits insert, unique on user + grant_source) and the selects
 * against credit_deposits / usage_events.
 */
function fakeDb(deposits: Deposit[]) {
  let failNext = 0;
  const balance = (u: string) =>
    deposits.filter((d) => d.user_id === u && (d.status === "confirmed" || d.status === "forwarded")).reduce((s, d) => s + d.amount_usd, 0);
  return {
    deposits,
    balance,
    failMirror(n = 1) {
      failNext = n;
    },
    async rpc(fn: string, args: { p_user: string; p_source: string; p_credits: number }) {
      if (fn !== "grant_code_credits") return { data: null, error: { message: `no fn ${fn}` } };
      if (failNext > 0) {
        failNext--;
        return { data: null, error: { message: "connection reset" } };
      }
      const dup = deposits.some((d) => d.user_id === args.p_user && d.grant_source === args.p_source);
      if (!dup) deposits.push({ user_id: args.p_user, amount_usd: args.p_credits, status: "confirmed", grant_source: args.p_source });
      return { data: { applied: !dup, balance: balance(args.p_user) }, error: null };
    },
    from(table: string) {
      const filters: Record<string, unknown> = {};
      const ins: Record<string, unknown[]> = {};
      const q = {
        select: () => q,
        eq: (col: string, v: unknown) => ((filters[col] = v), q),
        in: (col: string, v: unknown[]) => ((ins[col] = v), q),
        then: (resolve: (v: { data: unknown; error: null }) => void) => {
          if (table !== "credit_deposits") return resolve({ data: [], error: null });
          const rows = deposits.filter(
            (d) =>
              Object.entries(filters).every(([k, v]) => (d as Record<string, unknown>)[k] === v) &&
              Object.entries(ins).every(([k, v]) => v.includes((d as Record<string, unknown>)[k])),
          );
          resolve({ data: rows, error: null });
        },
      };
      return q;
    },
  };
}

function setup(users: Record<string, Partial<AuthInfo> & { balance?: number }>) {
  const deposits: Deposit[] = [];
  const auth = new Map<string, AuthInfo>();
  for (const [id, u] of Object.entries(users)) {
    deposits.push({ user_id: id, amount_usd: u.balance ?? 10, status: "confirmed", grant_source: null });
    auth.set(id, {
      email: u.email ?? `${id}@example.com`,
      confirmed: u.confirmed ?? true,
      banned: u.banned ?? false,
      createdAt: u.createdAt ?? new Date(NOW - 30 * DAY).toISOString(),
    });
  }
  const db = fakeDb(deposits);
  const now = () => NOW;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const anyDb = db as any;
  const deps: CreditDeps = {
    db: anyDb,
    credits: new Credits(creditMemory(), { now, onGrant: (u, g, s) => applyGrant(anyDb, u, g, s) }),
    affiliates: new Affiliates(affMemory(), { now, defaultQuota: 3, inviteTtlMs: 30 * DAY }),
    now,
    authUser: async (id) => auth.get(id) ?? null,
  };
  return { deps, db, auth };
}

describe("credit codes", () => {
  it("writes a redeemed code into the existing credit balance exactly once", async () => {
    const { deps, db } = setup({ alice: {}, bob: {} });
    const { code } = await mintCreditCode({ credits: 25, label: "test" }, deps);
    const r = await redeemCreditCode("alice", code.toLowerCase().replace(/-/g, " "), deps);
    expect(r).toMatchObject({ ok: true, credits: 25, balance: 35 });
    expect(db.balance("alice")).toBe(35);
    expect(db.deposits.filter((d) => d.grant_source?.startsWith("code:"))).toHaveLength(1);

    expect(await redeemCreditCode("alice", code, deps)).toMatchObject({ ok: false, reason: "already_redeemed" });
    expect(db.balance("alice")).toBe(35);

    expect(await redeemCreditCode("bob", code, deps)).toMatchObject({ ok: false, reason: "used_up" });
    expect(db.balance("bob")).toBe(10);
  });

  it("rejects unknown, revoked and expired codes", async () => {
    const { deps } = setup({ alice: {} });
    expect(await redeemCreditCode("alice", "CR-0000-0000-0000-0000", deps)).toMatchObject({ ok: false, reason: "invalid" });
    const revoked = await mintCreditCode({ credits: 5 }, deps);
    await deps.credits.revoke(revoked.id);
    expect(await redeemCreditCode("alice", revoked.code, deps)).toMatchObject({ ok: false, reason: "revoked" });
    const expired = await mintCreditCode({ credits: 5, expiresAt: NOW - 1 }, deps);
    expect(await redeemCreditCode("alice", expired.code, deps)).toMatchObject({ ok: false, reason: "expired" });
  });

  it("a multi-use code pays each user once", async () => {
    const { deps, db } = setup({ alice: {}, bob: {}, carl: {} });
    const { code } = await mintCreditCode({ credits: 3, maxRedemptions: 2 }, deps);
    expect((await redeemCreditCode("alice", code, deps)).ok).toBe(true);
    expect((await redeemCreditCode("bob", code, deps)).ok).toBe(true);
    expect(await redeemCreditCode("carl", code, deps)).toMatchObject({ ok: false, reason: "used_up" });
    expect([db.balance("alice"), db.balance("bob"), db.balance("carl")]).toEqual([13, 13, 10]);
  });

  it("repairs a mirror write that failed after the redemption committed", async () => {
    const { deps, db } = setup({ alice: {} });
    const { code } = await mintCreditCode({ credits: 40 }, deps);
    db.failMirror(1);
    await expect(redeemCreditCode("alice", code, deps)).rejects.toThrow(/grant_code_credits/);
    expect(db.balance("alice")).toBe(10);
    expect(await redeemCreditCode("alice", code, deps)).toMatchObject({ ok: false, reason: "already_redeemed" });
    expect(db.balance("alice")).toBe(50);
    await redeemCreditCode("alice", code, deps);
    expect(db.balance("alice")).toBe(50);
  });

  it("validates mint input", async () => {
    const { deps } = setup({});
    await expect(mintCreditCode({ credits: 0 }, deps)).rejects.toThrow(TypeError);
    await expect(mintCreditCode({ credits: 1.5 }, deps)).rejects.toThrow(TypeError);
    await expect(mintCreditCode({ credits: 10, maxRedemptions: 0 }, deps)).rejects.toThrow(TypeError);
  });
});

describe("invites", () => {
  const fresh = () => new Date(NOW - 1 * DAY).toISOString();

  it("locks invites for new, unconfirmed and disposable accounts", async () => {
    const { deps } = setup({
      young: { createdAt: new Date(NOW - (INVITE_MIN_ACCOUNT_AGE_DAYS - 1) * DAY).toISOString() },
      unconfirmed: { confirmed: false },
      junk: { email: "x@mailinator.com" },
    });
    await expect(createInvite("young", "", deps)).rejects.toMatchObject({ reason: "too_new" });
    await expect(createInvite("unconfirmed", "", deps)).rejects.toMatchObject({ reason: "unconfirmed" });
    await expect(createInvite("junk", "", deps)).rejects.toMatchObject({ reason: "blocked" });
  });

  it("gives every account exactly 3", async () => {
    const { deps } = setup({ alice: {} });
    for (let i = 0; i < 3; i++) await createInvite("alice", "", deps);
    await expect(createInvite("alice", "", deps)).rejects.toMatchObject({ reason: "no_invites_left" });
  });

  it("pays both sides once, only after the invitee confirms", async () => {
    const { deps, db, auth } = setup({ alice: {}, carol: { createdAt: fresh(), confirmed: false } });
    const inv = await createInvite("alice", "for carol", deps);
    expect((await deps.affiliates.quota("alice")).left).toBe(2);

    expect(await acceptInvite("carol", inv.code, deps)).toMatchObject({ ok: true, bonus: "pending", pendingReason: "email not confirmed" });
    expect([db.balance("alice"), db.balance("carol")]).toEqual([10, 10]);

    auth.get("carol")!.confirmed = true;
    expect(await settleInviteBonus("carol", deps)).toMatchObject({ status: "granted" });
    expect([db.balance("alice"), db.balance("carol")]).toEqual([10 + INVITE_BONUS_CREDITS, 10 + INVITE_BONUS_CREDITS]);

    expect(await settleInviteBonus("carol", deps)).toMatchObject({ status: "already" });
    await onSignedIn("carol", inv.code, deps);
    expect([db.balance("alice"), db.balance("carol")]).toEqual([10 + INVITE_BONUS_CREDITS, 10 + INVITE_BONUS_CREDITS]);

    const o = await inviteOverview("alice", deps);
    expect(o.invites[0]).toMatchObject({ status: "used", bonus: "granted" });
    expect(o.invites[0].usedByEmail).toMatch(/^ca\*+@example\.com$/);
  });

  it("holds the bonus for disposable, same-inbox and banned invitees", async () => {
    const { deps, db } = setup({
      alice: { email: "alice.smith@gmail.com" },
      sock: { email: "alicesmith+2@gmail.com", createdAt: fresh() },
      temp: { email: "t@yopmail.com", createdAt: fresh() },
      bad: { banned: true, createdAt: fresh() },
    });
    const [a, b, c] = [await createInvite("alice", "", deps), await createInvite("alice", "", deps), await createInvite("alice", "", deps)];
    expect(await acceptInvite("sock", a.code, deps)).toMatchObject({ ok: true, bonus: "pending", pendingReason: "same person" });
    expect(await acceptInvite("temp", b.code, deps)).toMatchObject({ ok: true, bonus: "pending", pendingReason: "disposable email" });
    expect(await acceptInvite("bad", c.code, deps)).toMatchObject({ ok: true, bonus: "pending", pendingReason: "account banned" });
    expect([db.balance("alice"), db.balance("sock"), db.balance("temp"), db.balance("bad")]).toEqual([10, 10, 10, 10]);
  });

  it("refuses old accounts and a second invite (app check and database index)", async () => {
    const { deps } = setup({ alice: {}, bob: {}, dan: { createdAt: fresh() }, eve: { createdAt: fresh() } });
    const a = await createInvite("alice", "", deps);
    const b = await createInvite("bob", "", deps);
    expect(await acceptInvite("bob", a.code, deps)).toMatchObject({ ok: false, reason: "not_new" });
    expect(await acceptInvite("dan", a.code, deps)).toMatchObject({ ok: true });
    expect(await acceptInvite("dan", b.code, deps)).toMatchObject({ ok: false, reason: "already_invited" });

    // A concurrent second accept slips past the read; the unique index refuses it.
    const c = await createInvite("bob", "", deps);
    const real = deps.affiliates.redeemInvite.bind(deps.affiliates);
    deps.affiliates.invitedBy = async () => null;
    deps.affiliates.redeemInvite = async () => {
      throw new Error('duplicate key value violates unique constraint "aff_invites_one_per_user"');
    };
    expect(await acceptInvite("eve", c.code, deps)).toMatchObject({ ok: false, reason: "already_invited" });
    deps.affiliates.redeemInvite = real;
  });

  it("only the owner can withdraw an unused invite", async () => {
    const { deps } = setup({ alice: {}, bob: {}, dan: { createdAt: fresh() } });
    const a = await createInvite("alice", "", deps);
    await expect(revokeInvite("bob", a.id, deps)).rejects.toMatchObject({ reason: "not_found" });
    await revokeInvite("alice", a.id, deps);
    expect(await acceptInvite("dan", a.code, deps)).toMatchObject({ ok: false, reason: "revoked" });
  });

  it("cleans codes and canonicalizes gmail aliases", () => {
    expect(cleanInviteCode(" INV-AB12-<script>")).toBe("INV-AB12-script");
    expect(canonicalEmail("A.Lice+x@GoogleMail.com")).toBe("alice@gmail.com");
    expect(canonicalEmail("a.lice+x@example.com")).toBe("a.lice@example.com");
  });
});
