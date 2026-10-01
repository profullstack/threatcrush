-- Public, read-only fix reports an AI agent can fetch (/r/<token>).
-- Created: 2026-10-01
--
-- Opt-in per organization: an owner or admin creates a link, and anyone
-- holding it can read the org's open hardening findings and a summary of
-- recent detections as markdown or JSON. Revoking sets revoked_at; the token
-- then answers 404 like one that never existed.

CREATE TABLE IF NOT EXISTS report_shares (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  -- 32 random bytes, base64url: unguessable, so the link is the credential.
  token TEXT NOT NULL UNIQUE CHECK (token ~ '^[A-Za-z0-9_-]{43}$'),
  created_by UUID REFERENCES user_profiles(id) ON DELETE SET NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMP WITH TIME ZONE,
  last_viewed_at TIMESTAMP WITH TIME ZONE
);

-- At most one live link per organization.
CREATE UNIQUE INDEX IF NOT EXISTS idx_report_shares_one_live
  ON report_shares(org_id) WHERE revoked_at IS NULL;

-- Service role only: every read and write goes through the API.
ALTER TABLE report_shares ENABLE ROW LEVEL SECURITY;
