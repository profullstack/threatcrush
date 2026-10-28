-- "Update now": let the dashboard ask a daemon to install the newest release
-- immediately (no min_age wait) and restart onto it. Same remediation-claim
-- channel as "restart". Daemons older than 0.13.57 answer "unsupported
-- action_type", so the dashboard sends those a restart instead (their updater
-- checks 10-40 minutes after start).
ALTER TABLE remediation_actions DROP CONSTRAINT IF EXISTS remediation_actions_action_type_check;
ALTER TABLE remediation_actions
  ADD CONSTRAINT remediation_actions_action_type_check
  CHECK (action_type IN ('block', 'unblock', 'allowlist_add', 'allowlist_remove', 'restart', 'update'));
