import { randomUUID } from "node:crypto";

/**
 * A small in-memory PostgREST stand-in for the incident code paths: select
 * with eq/neq/in/gte filters, order, limit, maybeSingle/single, head counts,
 * insert/update with .select(). The partial unique index on (org_id,
 * dedupe_key) where status <> 'resolved' is enforced (23505).
 */
export type Row = Record<string, unknown>;

export function fakeDb(tables: Record<string, Row[]>) {
  const t = (name: string) => (tables[name] ??= []);
  const uniqueViolation = (name: string, row: Row, selfId?: unknown) =>
    name === "incidents" &&
    ((row.human_code != null && t(name).some((r) => r.id !== selfId && r.human_code === row.human_code)) ||
      (row.status !== "resolved" &&
        t(name).some((r) => r.id !== selfId && r.org_id === row.org_id && r.dedupe_key === row.dedupe_key && r.status !== "resolved")));

  function from(name: string) {
    const filters: Array<(r: Row) => boolean> = [];
    let mode: "select" | "insert" | "update" = "select";
    let payload: Row | Row[] = {};
    let head = false;
    let limitN = Infinity;
    let orderBy: { col: string; asc: boolean } | null = null;

    const matching = () => t(name).filter((r) => filters.every((f) => f(r)));
    const exec = (): { data: unknown; error: unknown; count?: number } => {
      if (mode === "insert") {
        const rows = (Array.isArray(payload) ? payload : [payload]).map((r) => ({
          id: randomUUID(), created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
          status: name === "incidents" ? "open" : undefined, raise_count: name === "incidents" ? 1 : undefined, ...r,
        }));
        for (const r of rows) if (uniqueViolation(name, r)) return { data: null, error: { code: "23505", message: "duplicate key" } };
        t(name).push(...rows);
        return { data: rows, error: null };
      }
      if (mode === "update") {
        const hits = matching();
        for (const r of hits) if (uniqueViolation(name, { ...r, ...(payload as Row) }, r.id)) return { data: null, error: { code: "23505", message: "duplicate key" } };
        for (const r of hits) Object.assign(r, payload);
        return { data: hits, error: null };
      }
      let rows = matching();
      if (orderBy) {
        const { col, asc } = orderBy;
        rows = [...rows].sort((a, b) => String(a[col]).localeCompare(String(b[col])) * (asc ? 1 : -1));
      }
      rows = rows.slice(0, limitN);
      return head ? { data: null, error: null, count: rows.length } : { data: rows, error: null, count: rows.length };
    };

    const q = {
      select(_cols?: string, opts?: { count?: string; head?: boolean }) { if (opts?.head) head = true; return q; },
      insert(rows: Row | Row[]) { mode = "insert"; payload = rows; return q; },
      update(patch: Row) { mode = "update"; payload = patch; return q; },
      eq(c: string, v: unknown) { filters.push((r) => r[c] === v); return q; },
      neq(c: string, v: unknown) { filters.push((r) => r[c] !== v); return q; },
      in(c: string, vs: unknown[]) { filters.push((r) => vs.includes(r[c])); return q; },
      gte(c: string, v: string) { filters.push((r) => String(r[c]) >= v); return q; },
      order(col: string, o?: { ascending?: boolean }) { orderBy = { col, asc: o?.ascending !== false }; return q; },
      limit(n: number) { limitN = n; return q; },
      async maybeSingle() { const r = exec(); return { data: (r.data as Row[] | null)?.[0] ?? null, error: r.error }; },
      async single() {
        const r = exec();
        const row = (r.data as Row[] | null)?.[0] ?? null;
        return { data: row, error: r.error ?? (row ? null : { message: "no rows" }) };
      },
      then(resolve: (v: unknown) => void, reject?: (e: unknown) => void) {
        try { resolve(exec()); } catch (e) { reject?.(e); }
      },
    };
    return q;
  }
  return { from, tables } as unknown as import("@supabase/supabase-js").SupabaseClient & { tables: Record<string, Row[]> };
}
