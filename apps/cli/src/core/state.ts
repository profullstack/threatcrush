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

export function getEventCount(since?: Date): number {
  const database = tryDb();
  if (!database) return 0;
  if (since) {
    return (database.prepare(`SELECT COUNT(*) as count FROM events WHERE timestamp >= ?`)
      .get(since.toISOString()) as any).count;
  }
  return (database.prepare(`SELECT COUNT(*) as count FROM events`).get() as any).count;
}

export function getThreatCount(since?: Date): number {
  const database = tryDb();
  if (!database) return 0;
  const severities = "('medium','high','critical')";
  if (since) {
    return (database.prepare(
      `SELECT COUNT(*) as count FROM events WHERE severity IN ${severities} AND timestamp >= ?`
    ).get(since.toISOString()) as any).count;
  }
  return (database.prepare(
    `SELECT COUNT(*) as count FROM events WHERE severity IN ${severities}`
  ).get() as any).count;
}

export function getTopSources(limit: number = 10): Array<{ ip: string; count: number }> {
  const database = tryDb();
  if (!database) return [];
  return database.prepare(`
    SELECT source_ip as ip, COUNT(*) as count FROM events
    WHERE source_ip IS NOT NULL
    GROUP BY source_ip ORDER BY count DESC LIMIT ?
  `).all(limit) as any[];
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
