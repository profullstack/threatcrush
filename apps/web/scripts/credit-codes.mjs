#!/usr/bin/env node
// Mint, list and revoke ThreatCrush credit codes with the service role.
// 1 credit = $1.00 of credit balance. Codes are stored as sha256 only; the
// plaintext is printed once by `mint`.
//
//   SUPABASE_URL=… SUPABASE_SERVICE_ROLE_KEY=… node apps/web/scripts/credit-codes.mjs mint 25 "for Bob" [uses] [days]
//   … list
//   … revoke <codeId>
import { createClient } from "@supabase/supabase-js";
import { Credits, supabaseStore } from "@profullstack/redeem-credits";

const url = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!url || !key) {
  console.error("Set SUPABASE_URL (or NEXT_PUBLIC_SUPABASE_URL) and SUPABASE_SERVICE_ROLE_KEY.");
  process.exit(2);
}
const credits = new Credits(supabaseStore(createClient(url, key, { auth: { persistSession: false } })));
const [cmd = "list", ...args] = process.argv.slice(2);

if (cmd === "mint") {
  const amount = Number(args[0]);
  if (!Number.isInteger(amount) || amount < 1 || amount > 10000) {
    console.error("credits must be a whole number from 1 to 10000");
    process.exit(2);
  }
  const days = Number(args[3] ?? 0);
  const minted = await credits.mint({
    grant: { unit: "scan_credits", amount },
    label: (args[1] || `${amount} ThreatCrush credits`).slice(0, 200),
    maxRedemptions: Number(args[2] ?? 1) || 1,
    expiresAt: days > 0 ? Date.now() + days * 86400000 : null,
    createdBy: "scripts/credit-codes.mjs",
  });
  console.log(JSON.stringify(minted, null, 2));
} else if (cmd === "revoke") {
  await credits.revoke(String(args[0]));
  console.log("revoked", args[0]);
} else {
  for (const c of await credits.list()) {
    console.log(`${c.id}  ${c.grant.amount} ${c.grant.unit}  ${c.redemptions}/${c.maxRedemptions}${c.revokedAt ? "  revoked" : ""}  ${c.label}`);
  }
}
