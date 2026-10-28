#!/usr/bin/env node
// How many user_settings secrets are still legacy plaintext (inside the
// SETTINGS_ENCRYPTION_KEY wrapper) rather than browser-sealed
// (tc_e2e_secret_v1:)? Counts only; never prints a value. Run inside the app
// container, where SETTINGS_ENCRYPTION_KEY and the DB URL are set:
//   docker exec -i threatcrushcom-app-1 node - < scripts/settings-legacy-report.mjs
// Flip LEGACY_KEY_MIGRATION=off once legacy_values is 0 (or at the cutoff date).
import { createDecipheriv } from "node:crypto";

const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
const raw = process.env.SETTINGS_ENCRYPTION_KEY ?? "";
const k = Buffer.from(raw, "base64").length === 32 ? Buffer.from(raw, "base64") : Buffer.from(raw, "utf8");
const res = await fetch(
  `${url}/rest/v1/user_settings?select=user_id,payload_secret_ciphertext,payload_secret_iv,payload_secret_tag&payload_secret_ciphertext=not.is.null`,
  { headers: { apikey: key, Authorization: `Bearer ${key}` } },
);
const rows = await res.json();
let sealed = 0, legacy = 0, users = 0, unreadable = 0;
for (const r of rows) {
  try {
    const d = createDecipheriv("aes-256-gcm", k, Buffer.from(r.payload_secret_iv, "base64"), { authTagLength: 16 });
    d.setAuthTag(Buffer.from(r.payload_secret_tag, "base64"));
    const map = JSON.parse(Buffer.concat([d.update(Buffer.from(r.payload_secret_ciphertext, "base64")), d.final()]).toString("utf8"));
    const vals = Object.values(map).filter((v) => typeof v === "string");
    const l = vals.filter((v) => !v.startsWith("tc_e2e_secret_v1:")).length;
    legacy += l;
    sealed += vals.length - l;
    if (l) users++;
  } catch {
    unreadable++;
  }
}
console.log(JSON.stringify({ rows: rows.length, sealed_values: sealed, legacy_values: legacy, legacy_users: users, unreadable_rows: unreadable }));
