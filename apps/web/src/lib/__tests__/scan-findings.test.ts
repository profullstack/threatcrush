import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
import { fingerprintOf, normalizeFindings, syncRunFindings, urlSafe } from "@/lib/scan-findings";

type Row = Record<string, unknown>;

/** Just enough of supabase-js for syncRunFindings: select/update/insert with eq/in filters. */
function fakeDb() {
  const rows: Row[] = [];
  let seq = 0;
  const query = (op: "select" | "update", patch?: Row) => {
    const filters: ((r: Row) => boolean)[] = [];
    const q = {
      eq(k: string, v: unknown) { filters.push((r) => r[k] === v); return q; },
      in(k: string, vs: unknown[]) { filters.push((r) => vs.includes(r[k])); return q; },
      then(resolve: (v: { data: Row[]; error: null }) => void) {
        const hit = rows.filter((r) => filters.every((f) => f(r)));
        if (op === "update") for (const r of hit) Object.assign(r, patch);
        resolve({ data: hit.map((r) => ({ ...r })), error: null });
      },
    };
    return q;
  };
  const client = {
    from: () => ({
      select: () => query("select"),
      update: (patch: Row) => query("update", patch),
      insert: async (list: Row[]) => {
        for (const r of list) rows.push({ id: `f${++seq}`, status: "open", times_seen: 1, ...r });
        return { error: null };
      },
    }),
  };
  return { rows, client: client as never };
}

const run = (findings: unknown[], status = "succeeded", extra: Row = {}) => ({
  id: `r${Math.random()}`, org_id: "o1", property_id: "p1", type: "ai-scan", scope: "", status, findings, ...extra,
});
const F = (type: string, severity = "high") => ({ type, severity, message: `LLM01 ${type}`, location: "https://bot/chat", details: {} });

describe("normalizeFindings", () => {
  it("drops junk, defaults severity, dedupes one fingerprint to its most severe hit", () => {
    const out = normalizeFindings([null, 7, { message: "" }, { type: "x", message: "m", severity: "low" }, { type: "x", message: "m", severity: "critical" }, { type: "y", message: "n", severity: "weird" }]);
    expect(out).toHaveLength(2);
    expect(out.find((f) => f.type === "x")?.severity).toBe("critical");
    expect(out.find((f) => f.type === "y")?.severity).toBe("info");
  });
  it("returns nothing for a non-array", () => expect(normalizeFindings({})).toEqual([]));

  it("strips query strings and credentials from URL locations, leaves file locations alone", () => {
    const [f] = normalizeFindings([{ type: "p", message: "m", location: "https://u:pw@bot.example/chat?key=sk-123#x" }]);
    expect(f.location).toBe("https://bot.example/chat");
    expect(urlSafe("src/app.ts:12")).toBe("src/app.ts:12");
    expect(urlSafe("http://localhost:3000/chat?key=a")).toBe("http://localhost:3000/chat");
  });
});

describe("fingerprintOf", () => {
  it("keeps a code finding stable when its line moves", () => {
    const a = { type: "SQLi", message: "x", location: "a.ts:10", details: { ruleId: "R1", file: "a.ts", snippet: "db.query(q + id)" } };
    const b = { ...a, location: "a.ts:42", details: { ...a.details, line: 42 } };
    expect(fingerprintOf(a)).toBe(fingerprintOf(b));
    expect(fingerprintOf(a)).not.toBe(fingerprintOf({ ...a, details: { ...a.details, file: "b.ts" } }));
  });
  it("folds digits in messages", () => {
    const a = { type: "slow", message: "took 812ms", location: null };
    expect(fingerprintOf(a)).toBe(fingerprintOf({ ...a, message: "took 90ms" }));
  });
});

describe("syncRunFindings", () => {
  it("adds new findings, bumps ones seen again, fixes ones that are gone, reopens ones that come back", async () => {
    const { rows, client } = fakeDb();
    const first = await syncRunFindings(client, run([F("a"), F("b")]));
    expect(first).toMatchObject({ new: 2, seen: 0, reopened: 0, fixed: 0 });
    expect(first.raised.map((r) => [r.message, r.reopened])).toEqual([["LLM01 a", false], ["LLM01 b", false]]);
    const second = await syncRunFindings(client, run([F("a")]));
    expect(second).toMatchObject({ new: 0, seen: 1, reopened: 0, fixed: 1 });
    expect(second.raised).toEqual([]);
    const b = rows.find((r) => r.type === "b")!;
    expect(b.status).toBe("fixed");
    expect(b.resolved_at).toBeTruthy();
    expect(rows.find((r) => r.type === "a")!.times_seen).toBe(2);
    const third = await syncRunFindings(client, run([F("a"), F("b")]));
    expect(third).toMatchObject({ new: 0, seen: 1, reopened: 1, fixed: 0 });
    expect(third.raised).toEqual([{ severity: "high", message: "LLM01 b", location: "https://bot/chat", reopened: true }]);
    expect(b.status).toBe("open");
  });

  it("never overrides a person's false_positive / ignored, and keeps acknowledged when seen", async () => {
    const { rows, client } = fakeDb();
    await syncRunFindings(client, run([F("a"), F("b"), F("c")]));
    rows.find((r) => r.type === "a")!.status = "false_positive";
    rows.find((r) => r.type === "b")!.status = "ignored";
    rows.find((r) => r.type === "c")!.status = "acknowledged";
    await syncRunFindings(client, run([F("c")]));
    expect(rows.map((r) => r.status)).toEqual(["false_positive", "ignored", "acknowledged"]);
  });

  it("a failed run records what it saw but fixes nothing", async () => {
    const { rows, client } = fakeDb();
    await syncRunFindings(client, run([F("a"), F("b")]));
    expect((await syncRunFindings(client, run([F("a")], "failed"))).fixed).toBe(0);
    expect(rows.every((r) => r.status === "open")).toBe(true);
  });

  it("a narrower scope never fixes findings from a wider one", async () => {
    const { rows, client } = fakeDb();
    await syncRunFindings(client, run([F("a"), F("b")], "succeeded", { scope: "all" }));
    await syncRunFindings(client, run([], "succeeded", { scope: "categories=prompt-injection" }));
    expect(rows.filter((r) => r.scope === "all").every((r) => r.status === "open")).toBe(true);
  });

  it("ignores runs that are not scan/pentest/ai-scan or not finished", async () => {
    const { rows, client } = fakeDb();
    await syncRunFindings(client, run([F("a")], "succeeded", { type: "other" }));
    await syncRunFindings(client, run([F("a")], "running"));
    expect(rows).toHaveLength(0);
  });
});
