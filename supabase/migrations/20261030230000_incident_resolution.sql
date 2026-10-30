-- A closure records the action, verification and authenticated operator in the same row update.
-- Existing resolved incidents intentionally remain NULL: their remediation is unknown.
ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS resolution jsonb;
NOTIFY pgrst, 'reload schema';
