-- `threatcrush login` by link, and `threatcrush save`.
-- Created: 2026-10-01
--
-- A server has no browser and should not be handed a password. The CLI starts
-- a request bound to a PKCE challenge, prints a link, and waits; the operator
-- approves it in a browser where they are already signed in; the CLI redeems it
-- with the matching verifier and gets a session of its own. One session per
-- machine, because refresh tokens rotate and a shared one logs every other
-- holder out on its first refresh.

CREATE TABLE IF NOT EXISTS cli_login_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- base64url(SHA-256(code_verifier)); only S256 is accepted.
  code_challenge TEXT NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
  -- Shown both in the terminal and on the approval page, so the operator can
  -- tell the request they are approving is the one they started.
  user_code TEXT NOT NULL,
  device_name TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
  user_id UUID REFERENCES user_profiles(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW() + INTERVAL '10 minutes',
  approved_at TIMESTAMP WITH TIME ZONE,
  consumed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_cli_login_requests_expires ON cli_login_requests(expires_at);

-- Service role only: every read and write goes through /api/auth/cli/*.
ALTER TABLE cli_login_requests ENABLE ROW LEVEL SECURITY;

-- The daemon config a machine last saved with `threatcrush save`, secrets
-- redacted by the CLI before upload.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS config JSONB;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS config_saved_at TIMESTAMP WITH TIME ZONE;
