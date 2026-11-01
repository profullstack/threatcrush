ALTER TABLE public.incidents
  ADD COLUMN IF NOT EXISTS ai_triage jsonb;
