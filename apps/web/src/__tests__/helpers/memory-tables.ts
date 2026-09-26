import { randomUUID } from "node:crypto";

type Row = Record<string, unknown>;
type Result = { data: unknown; error: null };

/**
 * A stateful stand-in for the PostgREST builder, for code whose behavior
 * depends on what earlier writes left in a table (counts, windows, purges).
 * Supports insert / select / update / delete with eq, gt, lt, order, limit,
 * single and maybeSingle. Rows get a random `id` unless one is given.
 * Comparisons are plain JS `<` / `>`, which orders ISO-8601 timestamps
 * correctly as long as every value uses `toISOString()`.
 */
export function createMemoryTables(seed: Record<string, Row[]> = {}) {
  const tables: Record<string, Row[]> = {};
  for (const [name, rows] of Object.entries(seed)) tables[name] = rows.map((row) => ({ ...row }));

  function from(table: string) {
    const rows = (tables[table] ??= []);
    let op: "select" | "insert" | "update" | "delete" = "select";
    let payload: Row | Row[] | undefined;
    const filters: ((row: Row) => boolean)[] = [];
    let orderBy: { column: string; ascending: boolean } | undefined;
    let limit: number | undefined;
    let single = false;

    function run(): Result {
      if (op === "insert") {
        const inserted = (Array.isArray(payload) ? payload : [payload!]).map((row) => ({
          id: randomUUID(),
          ...row,
        }));
        rows.push(...inserted);
        return { data: single ? inserted[0] : inserted, error: null };
      }

      let matched = rows.filter((row) => filters.every((keep) => keep(row)));
      if (op === "delete") {
        for (const row of matched) rows.splice(rows.indexOf(row), 1);
        return { data: null, error: null };
      }
      if (op === "update") {
        for (const row of matched) Object.assign(row, payload);
        const updated = matched.map((row) => ({ ...row }));
        return { data: single ? (updated[0] ?? null) : updated, error: null };
      }

      if (orderBy) {
        const { column, ascending } = orderBy;
        matched = [...matched].sort((a, b) =>
          (a[column] as string) < (b[column] as string) ? (ascending ? -1 : 1) : ascending ? 1 : -1,
        );
      }
      if (limit !== undefined) matched = matched.slice(0, limit);
      const copies = matched.map((row) => ({ ...row }));
      return { data: single ? (copies[0] ?? null) : copies, error: null };
    }

    const builder = {
      select: () => builder,
      insert: (value: Row | Row[]) => ((op = "insert"), (payload = value), builder),
      update: (value: Row) => ((op = "update"), (payload = value), builder),
      delete: () => ((op = "delete"), builder),
      eq: (column: string, value: unknown) => (filters.push((row) => row[column] === value), builder),
      gt: (column: string, value: string) => (filters.push((row) => (row[column] as string) > value), builder),
      lt: (column: string, value: string) => (filters.push((row) => (row[column] as string) < value), builder),
      order: (column: string, opts: { ascending?: boolean } = {}) => (
        (orderBy = { column, ascending: opts.ascending !== false }), builder
      ),
      limit: (count: number) => ((limit = count), builder),
      single: () => ((single = true), Promise.resolve(run())),
      maybeSingle: () => ((single = true), Promise.resolve(run())),
      then: (resolve: (value: Result) => unknown, reject: (reason: unknown) => unknown) =>
        Promise.resolve().then(run).then(resolve, reject),
    };
    return builder;
  }

  return { tables, from };
}
