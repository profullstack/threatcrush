// Profullstack Pass (2026-11-07): a user who deposits $99 into their own
// CoinPay wallet gets a free month on every Profullstack property. ThreatCrush
// is pay-as-you-go credit, so the pass pays the smallest top-up (PASS_CREDITS
// scan credits, $1 each) once per pass through grant_code_credits(), keyed on
// 'coinpay-pass:<sub>:<expires_at>': a repeat sign-in during the same pass never
// pays twice, a renewal pays again.
//
// CoinPay reports the pass on userinfo, which is only seen at sign-in, so the
// callback stores coinpay_identities.pass_until and calls applyCoinpayPass().
import type { SupabaseClient } from "@supabase/supabase-js";
import type { CoinpayPass } from "@profullstack/coinpay-onboard/pass";

export { PASS_URL, passFromUserinfo } from "@profullstack/coinpay-onboard/pass";

/** The smallest top-up on /usage ($1), in scan credits ($1 each). */
export const PASS_CREDITS = 1;

export const passSource = (sub: string, expiresAt: Date) => `coinpay-pass:${sub}:${expiresAt.toISOString()}`;

export interface PassStore {
  setPassUntil(sub: string, until: string | null): Promise<void>;
  grantOnce(userId: string, credits: number, source: string): Promise<{ applied: boolean }>;
}

export async function applyCoinpayPass(
  store: PassStore,
  userId: string,
  sub: string,
  pass: CoinpayPass,
  now: Date = new Date(),
): Promise<boolean> {
  const active = pass.active && pass.expiresAt !== null && pass.expiresAt.getTime() > now.getTime();
  await store.setPassUntil(sub, active ? pass.expiresAt!.toISOString() : null);
  if (!active) return false;
  return (await store.grantOnce(userId, PASS_CREDITS, passSource(sub, pass.expiresAt!))).applied;
}

export function supabasePassStore(admin: SupabaseClient): PassStore {
  return {
    async setPassUntil(sub, until) {
      const { error } = await admin.from("coinpay_identities").update({ pass_until: until }).eq("sub", sub);
      if (error) throw new Error(`pass_until: ${error.message}`);
    },
    async grantOnce(userId, credits, source) {
      const { data, error } = await admin.rpc("grant_code_credits", { p_user: userId, p_source: source, p_credits: credits });
      if (error) throw new Error(`grant_code_credits: ${error.message}`);
      return { applied: Boolean((data as { applied?: boolean } | null)?.applied) };
    },
  };
}
