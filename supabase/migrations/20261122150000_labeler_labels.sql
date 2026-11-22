-- c0mpute DIP-0036: the ThreatCrush labeler's public, append-only label log.
-- Every label issued or retracted is one row; a retraction is a later row with
-- neg = true. Rows are never updated or deleted, so the log is auditable: the
-- trigger below refuses UPDATE/DELETE even for the service role.

CREATE TABLE IF NOT EXISTS labeler_labels (
  id BIGSERIAL PRIMARY KEY,
  src TEXT NOT NULL,
  uri TEXT NOT NULL CHECK (uri ~ '^sha256:[0-9a-f]{64}$'),
  val TEXT NOT NULL CHECK (val IN ('malware', 'phishing', 'cryptominer', 'spam')),
  neg BOOLEAN NOT NULL DEFAULT FALSE,
  cts TIMESTAMP WITH TIME ZONE NOT NULL,
  exp TIMESTAMP WITH TIME ZONE NOT NULL CHECK (exp > cts),
  evidence TEXT CHECK (evidence IS NULL OR length(evidence) <= 600),
  sig TEXT NOT NULL CHECK (sig ~ '^[A-Za-z0-9_-]{86}$'),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_labeler_labels_uri ON labeler_labels (uri, id DESC);

CREATE OR REPLACE FUNCTION labeler_labels_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'labeler_labels is append-only';
END;
$$;

DROP TRIGGER IF EXISTS trg_labeler_labels_append_only ON labeler_labels;
CREATE TRIGGER trg_labeler_labels_append_only
  BEFORE UPDATE OR DELETE ON labeler_labels
  FOR EACH ROW EXECUTE FUNCTION labeler_labels_append_only();

ALTER TABLE labeler_labels ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON labeler_labels FROM anon, authenticated;
-- The app reads and appends through the service role only. New tables get no
-- service_role grant on this self-hosted Supabase, so grant exactly what is used.
GRANT SELECT, INSERT ON labeler_labels TO service_role;
GRANT USAGE, SELECT ON SEQUENCE labeler_labels_id_seq TO service_role;
