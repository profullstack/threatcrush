-- Triage incidents with transparent, zero-cost rules. This ranks work and
-- recommends a first check; it never downgrades severity or closes an alert.
ALTER TABLE public.organizations
  ADD COLUMN IF NOT EXISTS auto_triage_incidents boolean NOT NULL DEFAULT false;

UPDATE public.organizations
SET auto_triage_incidents = true
WHERE slug = 'profullstack' AND auto_triage_incidents = false;

ALTER TABLE public.incidents
  ADD COLUMN IF NOT EXISTS triage jsonb;

CREATE OR REPLACE FUNCTION public.incident_triage_payload(
  p_title text,
  p_severity text,
  p_source text,
  p_summary text,
  p_findings jsonb,
  p_triaged_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  evidence text := lower(concat_ws(' ', p_title, p_summary, coalesce(p_findings, '[]'::jsonb)::text));
  category text;
  priority text;
  confidence numeric;
  disposition text := 'review_required';
  summary text;
  next_action text;
BEGIN
  IF p_source = 'daemon' AND evidence LIKE '%[test] threatcrush self-test%' THEN
    category := 'self_test';
    priority := 'P3';
    confidence := 0.99;
    disposition := 'test_signal';
    summary := 'The detection identifies itself as a ThreatCrush self-test; it is not evidence of an attack.';
    next_action := 'Confirm the self-test was intentional, then close this test alert.';
  ELSIF p_source = 'manual' AND p_title ILIKE '%/malware-test-prs'
      AND evidence LIKE '%vulns/%' THEN
    category := 'intentional_test_corpus';
    priority := 'P3';
    confidence := 0.96;
    disposition := 'likely_test_corpus';
    summary := 'Findings are in a repository named as a scanner test corpus and include intentional vulnerability fixtures.';
    next_action := 'Confirm the repository is isolated from production; then exclude its deliberate fixtures from the actionable queue.';
  ELSIF p_source = 'daemon' AND evidence LIKE '%new ssh key added%' THEN
    category := 'ssh_key_change';
    priority := 'P1';
    confidence := 0.90;
    summary := 'A new SSH key was observed. The alert does not establish whether the key was authorized.';
    next_action := 'Compare the fingerprint and account with the approved key inventory; revoke it and inspect authentication logs if it is unexpected.';
  ELSIF p_source = 'daemon' AND evidence LIKE '%ssh login accepted%' THEN
    category := 'ssh_login';
    priority := 'P2';
    confidence := 0.88;
    summary := 'A successful SSH login was recorded; success alone does not establish compromise.';
    next_action := 'Verify the account, source, and time against expected access and recent changes.';
  ELSIF p_source = 'daemon' AND evidence LIKE '%critical system error%' THEN
    category := 'system_error';
    priority := 'P1';
    confidence := 0.82;
    summary := 'The daemon reported a critical system error; the incident title alone does not establish its cause.';
    next_action := 'Review linked event evidence and service health, preserve logs, then contain only if compromise or impact is confirmed.';
  ELSIF evidence LIKE '%secret-%'
      OR evidence LIKE '%credential%'
      OR evidence LIKE '%private key%' THEN
    category := 'credential_exposure';
    priority := 'P1';
    confidence := 0.78;
    summary := 'A secret-scanner rule matched repository content; the finding does not prove the value is live.';
    next_action := 'Validate the flagged value with its provider; revoke confirmed active credentials, remove them from history, replace examples with placeholders, and rescan.';
  ELSIF evidence LIKE '%manifest-dependency-confusion%' THEN
    category := 'supply_chain';
    priority := 'P1';
    confidence := 0.77;
    summary := 'A dependency may resolve from an unintended package namespace.';
    next_action := 'Check package registry provenance and the lockfile, then pin the trusted package and review affected build workflows.';
  ELSIF evidence LIKE '%jwt%'
      OR evidence LIKE '%authentication%'
      OR evidence LIKE '%authorization%' THEN
    category := 'authentication';
    priority := 'P1';
    confidence := 0.73;
    summary := 'A possible authentication or authorization weakness needs a reachable-path check.';
    next_action := 'Trace the finding to its entry point and enforce signature, issuer, audience, and authorization checks before access is granted.';
  ELSIF evidence LIKE '%sql-%'
      OR evidence LIKE '%sql %'
      OR evidence LIKE '%sql/%'
      OR evidence LIKE '%query interpolation%' THEN
    category := 'sql_injection';
    priority := 'P1';
    confidence := 0.74;
    summary := 'A SQL construction pattern may allow untrusted input to alter a query.';
    next_action := 'Trace input to the query sink and replace string construction with bound parameters; add a regression test.';
  ELSIF evidence LIKE '%unsafe-deserialization%'
      OR evidence LIKE '%unserialize%'
      OR evidence LIKE '%deserialization%' THEN
    category := 'unsafe_deserialization';
    priority := 'P1';
    confidence := 0.76;
    summary := 'A deserialization path may process attacker-controlled data.';
    next_action := 'Verify whether input is untrusted; replace unsafe deserialization or constrain it to an authenticated, validated format.';
  ELSIF evidence LIKE '%shell-exec%'
      OR evidence LIKE '%command-injection%'
      OR evidence LIKE '%dynamic-code%'
      OR evidence LIKE '%dynamic execution%'
      OR evidence LIKE '%backtick-interpolation%'
      OR evidence LIKE '%eval-%' THEN
    category := 'code_execution';
    priority := 'P1';
    confidence := 0.74;
    summary := 'A command or dynamic-code pattern may execute attacker-controlled input.';
    next_action := 'Trace untrusted input to the execution sink and replace it with a fixed safe operation or allowlisted arguments; add a regression test.';
  ELSE
    category := 'security_review';
    priority := CASE WHEN p_severity IN ('critical', 'high') THEN 'P1' ELSE 'P2' END;
    confidence := 0.55;
    summary := 'Available incident metadata is not specific enough for a narrower classification.';
    next_action := 'Review the linked evidence, verify impact and affected asset, then record the finding-specific remediation.';
  END IF;

  RETURN jsonb_build_object(
    'version', 1,
    'engine', 'rules-v1',
    'category', category,
    'priority', priority,
    'confidence', confidence,
    'disposition', disposition,
    'needs_human_review', disposition <> 'test_signal',
    'summary', summary,
    'next_action', next_action,
    'severity_preserved', true,
    'triaged_at', p_triaged_at
  );
END;
$$;

CREATE OR REPLACE FUNCTION public.triage_incident_before_write()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.organizations AS o
    WHERE o.id = NEW.org_id AND o.auto_triage_incidents
  ) THEN
    NEW.triage := NULL;
    RETURN NEW;
  END IF;

  NEW.triage := public.incident_triage_payload(
    NEW.title, NEW.severity, NEW.source, NEW.summary, NEW.findings, now()
  );
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.incident_triage_payload(text, text, text, text, jsonb, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.triage_incident_before_write() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.triage_incident_before_write() FROM anon, authenticated;

DROP TRIGGER IF EXISTS incidents_auto_triage ON public.incidents;
CREATE TRIGGER incidents_auto_triage
  BEFORE INSERT OR UPDATE OF title, severity, source, summary, findings ON public.incidents
  FOR EACH ROW
  EXECUTE FUNCTION public.triage_incident_before_write();

-- Backfill the current queue through the same trigger used for future reports.
UPDATE public.incidents
SET title = title
WHERE status IN ('open', 'acknowledged')
  AND org_id IN (SELECT id FROM public.organizations WHERE auto_triage_incidents);

NOTIFY pgrst, 'reload schema';
