export type QueryResult = { data: unknown; error: unknown; count?: number | null };
export type QueryCall = [method: string, ...args: unknown[]];

/**
 * Chainable PostgREST query-builder stand-in. Every method call is appended to
 * `calls` and returns the builder; awaiting the builder (or calling
 * `.single()` / `.maybeSingle()`) resolves to `result`.
 */
export function recordQuery(result: QueryResult, calls: QueryCall[] = []): unknown {
  const target: Record<string, unknown> = {
    then: (resolve: (v: QueryResult) => unknown, reject: (e: unknown) => unknown) =>
      Promise.resolve(result).then(resolve, reject),
  };
  const proxy: unknown = new Proxy(target, {
    get(t, prop: string) {
      if (prop in t) return t[prop];
      return (...args: unknown[]) => {
        calls.push([prop, ...args]);
        return prop === "single" || prop === "maybeSingle" ? Promise.resolve(result) : proxy;
      };
    },
  });
  return proxy;
}
