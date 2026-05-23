import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedRequestUser, getAdminClient, unauthorized } from "@/lib/api-auth";
import {
  decryptSettingsSecret,
  encryptSettingsSecret,
  settingsCryptoConfigured,
  type CipherBlob,
} from "@/lib/settings-crypto";

type SettingsRow = {
  payload_plain: Record<string, unknown> | null;
  payload_secret_ciphertext: string | null;
  payload_secret_iv: string | null;
  payload_secret_tag: string | null;
  updated_at: string;
};

const KEY_RE = /^[A-Z][A-Z0-9_]{1,100}$/;

function rowToCipher(row: SettingsRow | null): CipherBlob | null {
  if (!row?.payload_secret_ciphertext || !row.payload_secret_iv || !row.payload_secret_tag) return null;
  return {
    ciphertext: row.payload_secret_ciphertext,
    iv: row.payload_secret_iv,
    tag: row.payload_secret_tag,
  };
}

function secretStatus(secrets: Record<string, string>) {
  return Object.fromEntries(
    Object.entries(secrets).map(([key, value]) => [key, { isSet: true, length: value.length }]),
  );
}

function sanitizePlain(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const out: Record<string, string | number | boolean | null> = {};
  for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
    if (!KEY_RE.test(key)) continue;
    if (typeof raw === "string" || typeof raw === "number" || typeof raw === "boolean" || raw === null) {
      out[key] = raw;
    }
  }
  return out;
}

function sanitizeSecrets(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const out: Record<string, string | null> = {};
  for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
    if (!KEY_RE.test(key)) continue;
    if (typeof raw === "string") out[key] = raw;
    else if (raw === null) out[key] = null;
  }
  return out;
}

async function loadSettings(userId: string) {
  const sb = getAdminClient();
  const { data, error } = await sb
    .from("user_settings")
    .select("payload_plain, payload_secret_ciphertext, payload_secret_iv, payload_secret_tag, updated_at")
    .eq("user_id", userId)
    .maybeSingle();
  if (error) throw new Error(error.message);
  return (data || null) as SettingsRow | null;
}

export async function GET(request: NextRequest) {
  const user = await getAuthenticatedRequestUser(request);
  if (!user) return unauthorized();

  let row: SettingsRow | null;
  try {
    row = await loadSettings(user.userId);
  } catch (error) {
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }

  let secrets: Record<string, string> = {};
  try {
    secrets = decryptSettingsSecret(rowToCipher(row));
  } catch {
    secrets = {};
  }

  return NextResponse.json({
    plain: row?.payload_plain || {},
    secrets: secretStatus(secrets),
    cryptoConfigured: settingsCryptoConfigured(),
    lastUpdatedAt: row?.updated_at || null,
  });
}

export async function PUT(request: NextRequest) {
  const user = await getAuthenticatedRequestUser(request);
  if (!user) return unauthorized();

  const body = await request.json().catch(() => null) as { plain?: unknown; secrets?: unknown } | null;
  if (!body || typeof body !== "object") {
    return NextResponse.json({ error: "JSON body is required" }, { status: 400 });
  }

  const plainUpdates = sanitizePlain(body.plain);
  const secretUpdates = sanitizeSecrets(body.secrets);

  let existing: SettingsRow | null;
  try {
    existing = await loadSettings(user.userId);
  } catch (error) {
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }

  const mergedPlain = { ...(existing?.payload_plain || {}), ...plainUpdates };
  for (const [key, value] of Object.entries(mergedPlain)) {
    if (value === null) delete mergedPlain[key];
  }

  let mergedSecrets: Record<string, string> = {};
  try {
    mergedSecrets = decryptSettingsSecret(rowToCipher(existing));
  } catch {
    mergedSecrets = {};
  }

  for (const [key, value] of Object.entries(secretUpdates)) {
    if (value === null || value.trim() === "") delete mergedSecrets[key];
    else mergedSecrets[key] = value;
  }

  let cipher: CipherBlob | null = rowToCipher(existing);
  if (Object.keys(secretUpdates).length > 0) {
    if (!settingsCryptoConfigured()) {
      return NextResponse.json(
        { error: "SETTINGS_ENCRYPTION_KEY is not configured" },
        { status: 503 },
      );
    }
    cipher = Object.keys(mergedSecrets).length > 0 ? encryptSettingsSecret(mergedSecrets) : null;
  }

  const row = {
    user_id: user.userId,
    payload_plain: mergedPlain,
    payload_secret_ciphertext: cipher?.ciphertext || null,
    payload_secret_iv: cipher?.iv || null,
    payload_secret_tag: cipher?.tag || null,
    updated_at: new Date().toISOString(),
  };

  const sb = getAdminClient();
  const { error } = await sb
    .from("user_settings")
    .upsert(row, { onConflict: "user_id" });

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({
    plain: mergedPlain,
    secrets: secretStatus(mergedSecrets),
    cryptoConfigured: settingsCryptoConfigured(),
    lastUpdatedAt: row.updated_at,
  });
}
