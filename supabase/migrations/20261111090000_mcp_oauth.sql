-- OAuth 2.1 for the MCP server at /api/mcp (ChatGPT apps, claude.ai custom
-- connectors, Claude Code), per the MCP authorization spec.
-- Created: 2026-11-11
--
--   oauth_clients  dynamic client registration (RFC 7591): public clients only
--                  (token_endpoint_auth_method none), so there is no secret.
--   oauth_codes    authorization codes: single use, ~5 minutes, bound to the
--                  client, redirect_uri, PKCE S256 challenge and the user.
--   oauth_tokens   one row per grant ("connected app"): the current access
--                  and refresh token hashes. A refresh rotates both in place.
--                  revoked_at ends the grant; it is listed and revocable on
--                  /account.
--
-- Only SHA-256 hashes of codes and tokens are stored. Service role only, like
-- every other credential table here (agent_keys, cli_login_requests): RLS on,
-- no policies, every read and write goes through the API (lib/mcp-oauth.ts).

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_name TEXT NOT NULL CHECK (length(client_name) BETWEEN 1 AND 200),
  redirect_uris TEXT[] NOT NULL CHECK (cardinality(redirect_uris) BETWEEN 1 AND 20),
  client_uri TEXT,
  logo_uri TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'mcp',
  resource TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  used_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON oauth_codes(expires_at);

CREATE TABLE IF NOT EXISTS oauth_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
  scope TEXT NOT NULL DEFAULT 'mcp',
  access_hash TEXT NOT NULL UNIQUE,
  refresh_hash TEXT NOT NULL UNIQUE,
  access_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  refresh_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMP WITH TIME ZONE,
  revoked_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user ON oauth_tokens(user_id);

ALTER TABLE oauth_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_tokens ENABLE ROW LEVEL SECURITY;

-- Supabase grants table privileges to anon/authenticated by default; RLS with
-- no policy already refuses them, this makes it explicit.
REVOKE ALL ON oauth_clients, oauth_codes, oauth_tokens FROM anon, authenticated;
