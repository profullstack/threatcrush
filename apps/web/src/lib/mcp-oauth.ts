import "server-only";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Principal } from "./access";

/**
 * OAuth 2.1 authorization server for the MCP resource at /api/mcp, per the MCP
 * authorization spec: protected-resource metadata (RFC 9728), authorization
 * server metadata (RFC 8414), dynamic client registration (RFC 7591), the
 * authorization code grant with PKCE S256 only, and rotating refresh tokens.
 * Public clients only (ChatGPT, claude.ai and Claude Code all register as
 * `token_endpoint_auth_method: none`).
 *
 * An access token acts as the user who approved it, the same Principal a
 * session token resolves to, but only on /api/mcp: it is resolved by the MCP
 * route, never by access.ts, so no other API accepts it. Tables:
 * supabase/migrations/*_mcp_oauth.sql (hashes only).
 */

export const ACCESS_PREFIX = "tc_oat_";
export const REFRESH_PREFIX = "tc_ort_";
export const SCOPE = "mcp";
export const ACCESS_TTL_S = 3600;
export const REFRESH_TTL_S = 90 * 24 * 3600;
export const CODE_TTL_S = 300;

const env = (name: string) => process.env[name];

/** The public origin, read at runtime (Next inlines literal process.env.X at build). */
export function siteOrigin(): string {
  return (env("NEXT_PUBLIC_APP_URL") || "https://threatcrush.com").replace(/\/+$/, "");
}

export const resourceUrl = (origin = siteOrigin()) => `${origin}/api/mcp`;
export const resourceMetadataUrl = (origin = siteOrigin()) => `${origin}/.well-known/oauth-protected-resource`;

export function protectedResourceMetadata(origin = siteOrigin()) {
  return {
    resource: resourceUrl(origin),
    authorization_servers: [origin],
    bearer_methods_supported: ["header"],
    scopes_supported: [SCOPE],
    resource_name: "ThreatCrush",
    resource_documentation: `${origin}/docs`,
  };
}

export function authorizationServerMetadata(origin = siteOrigin()) {
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/oauth/authorize`,
    token_endpoint: `${origin}/api/oauth/token`,
    registration_endpoint: `${origin}/api/oauth/register`,
    revocation_endpoint: `${origin}/api/oauth/revoke`,
    scopes_supported: [SCOPE],
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint_auth_methods_supported: ["none"],
    service_documentation: `${origin}/docs`,
  };
}

/** OpenID-shaped discovery for clients that only look there. No id_token is issued. */
export function openidConfiguration(origin = siteOrigin()) {
  return {
    ...authorizationServerMetadata(origin),
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
  };
}

/** CORS for the metadata, registration, token and revoke endpoints: no cookies are involved. */
export const CORS_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "authorization, content-type, mcp-protocol-version",
  "access-control-max-age": "86400",
};

// ─── Secrets ───

export const hashToken = (secret: string) => createHash("sha256").update(secret).digest("hex");
const secret = () => randomBytes(32).toString("base64url");

/** base64url(SHA-256(verifier)), constant-time against the stored challenge. */
export function pkceMatches(verifier: string, challenge: string): boolean {
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return false;
  const a = Buffer.from(createHash("sha256").update(verifier).digest("base64url"));
  const b = Buffer.from(challenge);
  return a.length === b.length && timingSafeEqual(a, b);
}

export const isS256Challenge = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z0-9_-]{43}$/.test(v);

// ─── Redirect URIs ───

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** https anywhere (no fragment, no credentials), or http on a loopback host (RFC 8252). */
export function isAllowedRedirectUri(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 2000) return false;
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return false;
  }
  if (u.hash || u.username || u.password) return false;
  if (u.protocol === "https:") return true;
  return u.protocol === "http:" && LOOPBACK.has(u.hostname);
}

/**
 * Exact match, except that a loopback redirect may use any port (RFC 8252
 * §7.3): Claude Code listens on whichever port is free.
 */
export function redirectUriMatches(registered: string[], asked: string): boolean {
  if (registered.includes(asked)) return true;
  let a: URL;
  try {
    a = new URL(asked);
  } catch {
    return false;
  }
  if (a.protocol !== "http:" || !LOOPBACK.has(a.hostname)) return false;
  return registered.some((r) => {
    try {
      const u = new URL(r);
      return u.protocol === "http:" && u.hostname === a.hostname && u.pathname === a.pathname && u.search === a.search;
    } catch {
      return false;
    }
  });
}

// ─── Errors ───

export class OAuthError extends Error {
  constructor(
    public code: string,
    message: string,
    public status = 400,
  ) {
    super(message);
  }
  body() {
    return { error: this.code, error_description: this.message };
  }
}

// ─── Clients (RFC 7591) ───

export interface OAuthClient {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  client_uri: string | null;
  logo_uri: string | null;
}

const cleanName = (v: unknown) =>
  typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f<>]/g, "").trim().slice(0, 100) : "";

const optionalHttps = (v: unknown) => {
  if (typeof v !== "string") return null;
  try {
    return new URL(v).protocol === "https:" ? v.slice(0, 500) : null;
  } catch {
    return null;
  }
};

export async function registerClient(admin: SupabaseClient, body: Record<string, unknown>) {
  const uris = body.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > 20) {
    throw new OAuthError("invalid_redirect_uri", "redirect_uris must list 1 to 20 URIs");
  }
  for (const u of uris) {
    if (!isAllowedRedirectUri(u)) {
      throw new OAuthError("invalid_redirect_uri", `Not allowed: ${String(u).slice(0, 200)} (https, or http on localhost/127.0.0.1)`);
    }
  }
  const method = body.token_endpoint_auth_method ?? "none";
  if (method !== "none") {
    throw new OAuthError("invalid_client_metadata", "Only public clients are supported: token_endpoint_auth_method must be none");
  }
  const grants = Array.isArray(body.grant_types) ? body.grant_types.map(String) : ["authorization_code", "refresh_token"];
  if (grants.some((g) => g !== "authorization_code" && g !== "refresh_token")) {
    throw new OAuthError("invalid_client_metadata", "grant_types may only be authorization_code and refresh_token");
  }
  const types = Array.isArray(body.response_types) ? body.response_types.map(String) : ["code"];
  if (types.some((t) => t !== "code")) throw new OAuthError("invalid_client_metadata", "response_types may only be code");

  const row = {
    client_id: `tc_client_${randomBytes(16).toString("hex")}`,
    client_name: cleanName(body.client_name) || "MCP client",
    redirect_uris: [...new Set(uris as string[])],
    client_uri: optionalHttps(body.client_uri),
    logo_uri: optionalHttps(body.logo_uri),
  };
  const { error } = await admin.from("oauth_clients").insert(row);
  if (error) throw new OAuthError("server_error", "Could not register the client", 500);
  return {
    ...row,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    scope: SCOPE,
  };
}

export async function getClient(admin: SupabaseClient, clientId: unknown): Promise<OAuthClient | null> {
  if (typeof clientId !== "string" || !/^[\w-]{1,100}$/.test(clientId)) return null;
  const { data } = await admin
    .from("oauth_clients")
    .select("client_id, client_name, redirect_uris, client_uri, logo_uri")
    .eq("client_id", clientId)
    .maybeSingle();
  return (data as OAuthClient | null) ?? null;
}

// ─── Authorization request ───

export interface AuthorizeParams {
  response_type?: unknown;
  client_id?: unknown;
  redirect_uri?: unknown;
  code_challenge?: unknown;
  code_challenge_method?: unknown;
  state?: unknown;
  scope?: unknown;
  resource?: unknown;
}

export type AuthorizeCheck =
  /** Unknown client or redirect: show the error, never redirect (RFC 6749 §4.1.2.1). */
  | { ok: false; error: string; description: string }
  /** The redirect is trusted but the request is bad: send the error back to the client. */
  | { ok: false; redirect: string }
  | { ok: true; client: OAuthClient; redirectUri: string; challenge: string; state: string | null; resource: string | null };

export function errorRedirect(redirectUri: string, error: string, description: string, state: string | null): string {
  const u = new URL(redirectUri);
  u.searchParams.set("error", error);
  u.searchParams.set("error_description", description);
  if (state) u.searchParams.set("state", state);
  u.searchParams.set("iss", siteOrigin());
  return u.toString();
}

export async function checkAuthorize(admin: SupabaseClient, p: AuthorizeParams): Promise<AuthorizeCheck> {
  const client = await getClient(admin, p.client_id);
  if (!client) return { ok: false, error: "invalid_client", description: "Unknown client_id. Remove the connector and add it again." };
  const redirectUri = typeof p.redirect_uri === "string" && p.redirect_uri ? p.redirect_uri : client.redirect_uris.length === 1 ? client.redirect_uris[0] : "";
  if (!redirectUri || !redirectUriMatches(client.redirect_uris, redirectUri)) {
    return { ok: false, error: "invalid_request", description: "redirect_uri is not registered for this client." };
  }
  const state = typeof p.state === "string" && p.state ? p.state.slice(0, 1000) : null;
  const back = (error: string, description: string) => ({ ok: false as const, redirect: errorRedirect(redirectUri, error, description, state) });
  if (p.response_type !== "code") return back("unsupported_response_type", "response_type must be code");
  if (!isS256Challenge(p.code_challenge)) return back("invalid_request", "PKCE is required: code_challenge (S256)");
  if (p.code_challenge_method !== "S256") return back("invalid_request", "code_challenge_method must be S256");
  if (typeof p.scope === "string" && p.scope.trim() && !p.scope.split(/\s+/).every((s) => s === SCOPE)) {
    return back("invalid_scope", `The only scope is ${SCOPE}`);
  }
  let resource: string | null = null;
  if (typeof p.resource === "string" && p.resource) {
    if (!resourceMatches(p.resource)) return back("invalid_target", `resource must be ${resourceUrl()}`);
    resource = p.resource;
  }
  return { ok: true, client, redirectUri, challenge: p.code_challenge, state, resource };
}

/** The MCP resource, with or without a trailing slash or query (the ?login variant). */
function resourceMatches(value: string): boolean {
  try {
    const u = new URL(value);
    const r = new URL(resourceUrl());
    return u.origin === r.origin && u.pathname.replace(/\/+$/, "") === r.pathname;
  } catch {
    return false;
  }
}

/** Issue a single-use code for an approved request; returns the redirect with code + state. */
export async function issueCode(
  admin: SupabaseClient,
  check: Extract<AuthorizeCheck, { ok: true }>,
  userId: string,
): Promise<string> {
  const code = secret();
  const { error } = await admin.from("oauth_codes").insert({
    code_hash: hashToken(code),
    client_id: check.client.client_id,
    user_id: userId,
    redirect_uri: check.redirectUri,
    code_challenge: check.challenge,
    scope: SCOPE,
    resource: check.resource,
    expires_at: new Date(Date.now() + CODE_TTL_S * 1000).toISOString(),
  });
  if (error) throw new OAuthError("server_error", "Could not issue an authorization code", 500);
  const u = new URL(check.redirectUri);
  u.searchParams.set("code", code);
  if (check.state) u.searchParams.set("state", check.state);
  u.searchParams.set("iss", siteOrigin());
  return u.toString();
}

// ─── Token endpoint ───

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
}

function newPair() {
  const access = ACCESS_PREFIX + secret();
  const refresh = REFRESH_PREFIX + secret();
  const now = Date.now();
  return {
    access,
    refresh,
    row: {
      access_hash: hashToken(access),
      refresh_hash: hashToken(refresh),
      access_expires_at: new Date(now + ACCESS_TTL_S * 1000).toISOString(),
      refresh_expires_at: new Date(now + REFRESH_TTL_S * 1000).toISOString(),
    },
  };
}

const respond = (access: string, refresh: string): TokenResponse => ({
  access_token: access,
  token_type: "Bearer",
  expires_in: ACCESS_TTL_S,
  refresh_token: refresh,
  scope: SCOPE,
});

export async function exchangeCode(admin: SupabaseClient, p: Record<string, unknown>): Promise<TokenResponse> {
  const code = typeof p.code === "string" ? p.code : "";
  const verifier = typeof p.code_verifier === "string" ? p.code_verifier : "";
  if (!code) throw new OAuthError("invalid_request", "code is required");
  if (!verifier) throw new OAuthError("invalid_request", "code_verifier is required (PKCE)");

  // Single use: the conditional update is the guard, so two racing requests cannot both redeem it.
  const { data: row } = await admin
    .from("oauth_codes")
    .update({ used_at: new Date().toISOString() })
    .eq("code_hash", hashToken(code))
    .is("used_at", null)
    .gt("expires_at", new Date().toISOString())
    .select("client_id, user_id, redirect_uri, code_challenge, scope")
    .maybeSingle();
  if (!row) throw new OAuthError("invalid_grant", "The authorization code is invalid, expired or already used");
  if (typeof p.client_id === "string" && p.client_id && p.client_id !== row.client_id) {
    throw new OAuthError("invalid_grant", "The code was issued to another client");
  }
  if (p.redirect_uri !== row.redirect_uri) throw new OAuthError("invalid_grant", "redirect_uri does not match the authorization request");
  if (!pkceMatches(verifier, row.code_challenge)) throw new OAuthError("invalid_grant", "code_verifier does not match the code_challenge");

  const pair = newPair();
  const { error } = await admin.from("oauth_tokens").insert({
    client_id: row.client_id,
    user_id: row.user_id,
    scope: row.scope,
    ...pair.row,
  });
  if (error) throw new OAuthError("server_error", "Could not issue tokens", 500);
  await admin.from("oauth_clients").update({ last_used_at: new Date().toISOString() }).eq("client_id", row.client_id);
  return respond(pair.access, pair.refresh);
}

export async function refreshTokens(admin: SupabaseClient, p: Record<string, unknown>): Promise<TokenResponse> {
  const refresh = typeof p.refresh_token === "string" ? p.refresh_token : "";
  if (!refresh.startsWith(REFRESH_PREFIX)) throw new OAuthError("invalid_grant", "The refresh token is invalid");
  const oldHash = hashToken(refresh);
  const { data: grant } = await admin
    .from("oauth_tokens")
    .select("id, client_id")
    .eq("refresh_hash", oldHash)
    .is("revoked_at", null)
    .gt("refresh_expires_at", new Date().toISOString())
    .maybeSingle();
  if (!grant) throw new OAuthError("invalid_grant", "The refresh token is invalid, expired or revoked");
  if (typeof p.client_id === "string" && p.client_id && p.client_id !== grant.client_id) {
    throw new OAuthError("invalid_grant", "The refresh token was issued to another client");
  }
  // Rotate in place, conditional on the old hash: a replayed refresh token loses the race.
  const pair = newPair();
  const { data: rotated } = await admin
    .from("oauth_tokens")
    .update(pair.row)
    .eq("id", grant.id)
    .eq("refresh_hash", oldHash)
    .select("id")
    .maybeSingle();
  if (!rotated) throw new OAuthError("invalid_grant", "The refresh token was already used");
  return respond(pair.access, pair.refresh);
}

/** RFC 7009: always 200, whether or not the token was known. Ends the whole grant. */
export async function revokeToken(admin: SupabaseClient, token: string): Promise<void> {
  const col = token.startsWith(ACCESS_PREFIX) ? "access_hash" : token.startsWith(REFRESH_PREFIX) ? "refresh_hash" : null;
  if (!col) return;
  await admin.from("oauth_tokens").update({ revoked_at: new Date().toISOString() }).eq(col, hashToken(token)).is("revoked_at", null);
}

// ─── Resolving an access token (MCP route only) ───

export async function resolveAccessToken(admin: SupabaseClient, token: string): Promise<Principal | null> {
  if (!token.startsWith(ACCESS_PREFIX)) return null;
  const { data: grant } = await admin
    .from("oauth_tokens")
    .select("id, user_id, last_used_at")
    .eq("access_hash", hashToken(token))
    .is("revoked_at", null)
    .gt("access_expires_at", new Date().toISOString())
    .maybeSingle();
  if (!grant) return null;
  // At most one write a minute per grant.
  if (!grant.last_used_at || Date.now() - Date.parse(grant.last_used_at) > 60_000) {
    await admin.from("oauth_tokens").update({ last_used_at: new Date().toISOString() }).eq("id", grant.id);
  }
  const { data: profile } = await admin.from("user_profiles").select("email").eq("id", grant.user_id).maybeSingle();
  return { kind: "user", userId: grant.user_id, email: (profile?.email as string | undefined) ?? null };
}

// ─── Connected apps (/account) ───

export async function listGrants(admin: SupabaseClient, userId: string) {
  const { data } = await admin
    .from("oauth_tokens")
    .select("id, client_id, scope, created_at, last_used_at, oauth_clients(client_name, client_uri)")
    .eq("user_id", userId)
    .is("revoked_at", null)
    .gt("refresh_expires_at", new Date().toISOString())
    .order("created_at", { ascending: false });
  return (data ?? []).map((g: Record<string, unknown>) => {
    const c = (Array.isArray(g.oauth_clients) ? g.oauth_clients[0] : g.oauth_clients) as { client_name?: string; client_uri?: string } | null;
    return {
      id: g.id as string,
      client_name: c?.client_name ?? "MCP client",
      client_uri: c?.client_uri ?? null,
      scope: g.scope as string,
      created_at: g.created_at as string,
      last_used_at: (g.last_used_at as string | null) ?? null,
    };
  });
}

export async function revokeGrant(admin: SupabaseClient, userId: string, id: string): Promise<boolean> {
  const { data } = await admin
    .from("oauth_tokens")
    .update({ revoked_at: new Date().toISOString() })
    .eq("id", id)
    .eq("user_id", userId)
    .is("revoked_at", null)
    .select("id")
    .maybeSingle();
  return Boolean(data);
}
