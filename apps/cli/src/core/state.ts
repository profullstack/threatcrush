import Database from 'better-sqlite3';
import type { ThreatEvent } from '../types/events.js';

let db: Database.Database | null = null;
let dbUnavailable = false;

export function isStateDbAvailable(): boolean {
  return db !== null;
}

export function initStateDB(dbPath: string = '/var/lib/threatcrush/state.db'): Database.Database {
  if (db) return db;
  if (dbUnavailable) {
    throw new Error('state db unavailable (previous init failed)');
  }

  try {
    try {
      db = new Database(dbPath);
    } catch {
      // Fall back to in-memory if we can't write to the path
      db = new Database(':memory:');
    }
  } catch (err) {
    // Native binding missing or unloadable — mark DB unavailable so callers
    // can degrade gracefully instead of throwing on every IPC request.
    dbUnavailable = true;
    throw err;
  }

  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      module TEXT NOT NULL,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      message TEXT NOT NULL,
      source_ip TEXT,
      details TEXT
    );

    CREATE TABLE IF NOT EXISTS module_state (
      module TEXT NOT NULL,
      key TEXT NOT NULL,
      value TEXT,
      PRIMARY KEY (module, key)
    );

    CREATE TABLE IF NOT EXISTS stats (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_module ON events(module);
    CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
    CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
  `);

  return db;
}

export function insertEvent(event: ThreatEvent): number {
  const database = tryDb();
  if (!database) return -1;
  const stmt = database.prepare(`
    INSERT INTO events (timestamp, module, category, severity, message, source_ip, details)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  const result = stmt.run(
    event.timestamp.toISOString(),
    event.module,
    event.category,
    event.severity,
    event.message,
    event.source_ip || null,
    event.details ? JSON.stringify(event.details) : null,
  );
  return result.lastInsertRowid as number;
}

function tryDb(): Database.Database | null {
  if (db) return db;
  if (dbUnavailable) return null;
  try {
    return initStateDB();
  } catch {
    return null;
  }
}

export function getRecentEvents(limit: number = 50): ThreatEvent[] {
  const database = tryDb();
  if (!database) return [];
  const rows = database.prepare(`
    SELECT * FROM events ORDER BY timestamp DESC LIMIT ?
  `).all(limit) as any[];
  return rows.map(rowToEvent);
}

// Every query the daemon answers over IPC must cost the same on a 50 MB
// database as on an 85 GB one: better-sqlite3 is synchronous, so a scan of the
// whole events table freezes the daemon, and a ban sent from the dashboard
// times out behind it. Counts and top sources therefore look at the newest
// RECENT_WINDOW events only (newest by id, which is the primary key).
export const RECENT_WINDOW = 200_000;

/** Events ever recorded (the AUTOINCREMENT sequence): O(1), never a scan. */
function eventsEverRecorded(database: Database.Database): number {
  const row = database.prepare(`SELECT seq FROM sqlite_sequence WHERE name = 'events'`).get() as { seq?: number } | undefined;
  return row?.seq ?? 0;
}

export function getEventCount(since?: Date): number {
  const database = tryDb();
  if (!database) return 0;
  if (since) {
    return (database.prepare(
      `SELECT COUNT(*) as count FROM (SELECT timestamp FROM events ORDER BY id DESC LIMIT ?) WHERE timestamp >= ?`,
    ).get(RECENT_WINDOW, since.toISOString()) as any).count;
  }
  return eventsEverRecorded(database);
}

export function getThreatCount(since?: Date): number {
  const database = tryDb();
  if (!database) return 0;
  const severities = "('medium','high','critical')";
  const cutoff = since ? since.toISOString() : '';
  return (database.prepare(
    `SELECT COUNT(*) as count FROM (SELECT severity, timestamp FROM events ORDER BY id DESC LIMIT ?)
     WHERE severity IN ${severities} AND timestamp >= ?`,
  ).get(RECENT_WINDOW, cutoff) as any).count;
}

export function getTopSources(limit: number = 10): Array<{ ip: string; count: number }> {
  const database = tryDb();
  if (!database) return [];
  return database.prepare(`
    SELECT source_ip as ip, COUNT(*) as count
    FROM (SELECT source_ip FROM events ORDER BY id DESC LIMIT ?)
    WHERE source_ip IS NOT NULL
    GROUP BY source_ip ORDER BY count DESC LIMIT ?
  `).all(RECENT_WINDOW, limit) as any[];
}

export const DEFAULT_EVENT_RETENTION_SECONDS = 14 * 86_400;
export const DEFAULT_MAX_EVENTS = 2_000_000;

/**
 * Deletes events older than the retention, and beyond the row cap, in small
 * batches so no single call holds the daemon for long. Returns how many went.
 * The file does not shrink (SQLite reuses the space), which is what we want:
 * it stops growing.
 */
export function pruneEvents(
  opts: { retentionSeconds?: number; maxEvents?: number; batch?: number; maxBatches?: number; now?: number } = {},
): number {
  const database = tryDb();
  if (!database) return 0;
  const retention = opts.retentionSeconds ?? DEFAULT_EVENT_RETENTION_SECONDS;
  const maxEvents = opts.maxEvents ?? DEFAULT_MAX_EVENTS;
  const batch = opts.batch ?? 5_000;
  const maxBatches = opts.maxBatches ?? 20;
  const cutoff = new Date((opts.now ?? Date.now()) - retention * 1000).toISOString();
  const byAge = database.prepare(
    `DELETE FROM events WHERE id IN (SELECT id FROM events WHERE timestamp < ? ORDER BY id LIMIT ?)`,
  );
  const lowest = database.prepare(`SELECT MIN(id) as lo, MAX(id) as hi FROM events`);
  const byCount = database.prepare(`DELETE FROM events WHERE id < ?`);
  let deleted = 0;
  for (let i = 0; i < maxBatches; i++) {
    const n = byAge.run(cutoff, batch).changes;
    deleted += n;
    if (n < batch) break;
  }
  // Ids are dense apart from what was deleted, so hi - cap is where to cut;
  // one batch at a time from the bottom.
  for (let i = 0; i < maxBatches; i++) {
    const { lo, hi } = lowest.get() as { lo: number | null; hi: number | null };
    if (lo === null || hi === null || hi - lo + 1 <= maxEvents) break;
    const n = byCount.run(Math.min(lo + batch, hi - maxEvents + 1)).changes;
    deleted += n;
    if (n === 0) break;
  }
  return deleted;
}

export function getModuleState(module: string, key: string): unknown {
  const database = db || initStateDB();
  const row = database.prepare(`SELECT value FROM module_state WHERE module = ? AND key = ?`)
    .get(module, key) as any;
  if (!row) return undefined;
  try {
    return JSON.parse(row.value);
  } catch {
    return row.value;
  }
}

export function setModuleState(module: string, key: string, value: unknown): void {
  const database = db || initStateDB();
  database.prepare(`
    INSERT OR REPLACE INTO module_state (module, key, value) VALUES (?, ?, ?)
  `).run(module, key, JSON.stringify(value));
}

function rowToEvent(row: any): ThreatEvent {
  return {
    id: row.id,
    timestamp: new Date(row.timestamp),
    module: row.module,
    category: row.category,
    severity: row.severity,
    message: row.message,
    source_ip: row.source_ip,
    details: row.details ? JSON.parse(row.details) : undefined,
  };
}

export function closeDB(): void {
  if (db) {
    db.close();
    db = null;
  }
}
