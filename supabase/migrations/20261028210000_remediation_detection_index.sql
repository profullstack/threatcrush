-- remediation_actions.detection_id references detections ON DELETE SET NULL
-- but had no index, so deleting a server (which cascades to its detections)
-- seq-scanned remediation_actions once per detection: removing seed1 (13,038
-- detections) ran for minutes; with this index it takes under a second.
-- Applied to prod by hand 2026-10-28 (CONCURRENTLY, so not in a transaction).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_remediation_detection
  ON remediation_actions (detection_id)
  WHERE detection_id IS NOT NULL;
