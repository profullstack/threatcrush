-- "Restart all": let the dashboard queue a daemon restart, carried on the same
-- remediation-claim channel the daemon already polls.
-- Created: 2026-10-01

ALTER TABLE remediation_actions DROP CONSTRAINT IF EXISTS remediation_actions_action_type_check;
ALTER TABLE remediation_actions
  ADD CONSTRAINT remediation_actions_action_type_check
  CHECK (action_type IN ('block', 'unblock', 'allowlist_add', 'allowlist_remove', 'restart'));
