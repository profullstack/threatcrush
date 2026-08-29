import { describe, it, expect, vi, beforeEach } from "vitest";
import { CHECKLIST, CHECKLIST_TOTAL } from "@/content/ctem-guide.generated";

// ─── Supabase mock ───

const rpc = vi.fn().mockResolvedValue({ error: null });
const insert = vi.fn().mockResolvedValue({ error: null });

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    rpc: (...args: unknown[]) => rpc(...args),
    from: () => ({ insert: (row: unknown) => insert(row) }),
  }),
}));

// Resend is fire-and-forget; keep it off the wire.
vi.mock("resend", () => ({
  Resend: class {
    emails = { send: vi.fn().mockResolvedValue({ error: null }) };
  },
}));

import { POST } from "@/app/api/checklist/route";

function makeRequest(body: unknown) {
  return new Request("http://localhost/api/checklist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

const allIds = CHECKLIST.stages.flatMap((s) => s.items.map((i) => i.id));

describe("POST /api/checklist", () => {
  beforeEach(() => {
    rpc.mockClear();
    insert.mockClear();
    process.env.RESEND_API_KEY = "test-key";
  });

  it("rejects a payload with no session id", async () => {
    const res = await POST(makeRequest({ answers: [] }));
    expect(res.status).toBe(400);
  });

  it("scores an empty checklist as 0", async () => {
    const res = await POST(makeRequest({ session_id: "s1", answers: [] }));
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.score).toBe(0);
  });

  it("scores a fully ticked checklist as 100", async () => {
    const res = await POST(makeRequest({ session_id: "s1", answers: allIds }));
    const body = await res.json();
    expect(body.score).toBe(100);
    expect(body.band).toBe("Optimizing");
  });

  it("ignores unknown ids so a junk payload cannot inflate the score", async () => {
    const res = await POST(
      makeRequest({
        session_id: "s1",
        answers: [...allIds, "not-a-real-control", "another-fake"],
      }),
    );
    const body = await res.json();
    expect(body.score).toBe(100);

    const [, args] = rpc.mock.calls[0] as [string, { p_answers: string[] }];
    expect(args.p_answers).toHaveLength(CHECKLIST_TOTAL);
  });

  it("deduplicates repeated ids", async () => {
    const id = allIds[0];
    const res = await POST(
      makeRequest({ session_id: "s1", answers: [id, id, id, id, id] }),
    );
    const body = await res.json();
    expect(body.score).toBe(Math.round((1 / CHECKLIST_TOTAL) * 100));
  });

  it("recomputes the score and ignores a client-supplied one", async () => {
    const res = await POST(
      makeRequest({ session_id: "s1", answers: [allIds[0]], score: 100 }),
    );
    const body = await res.json();
    expect(body.score).not.toBe(100);
  });

  it("records anonymously without creating a lead when no email is given", async () => {
    await POST(makeRequest({ session_id: "s1", answers: [allIds[0]] }));
    expect(rpc).toHaveBeenCalledWith("record_reader_checklist", expect.any(Object));
    expect(insert).not.toHaveBeenCalled();
  });

  it("creates a lead carrying the score when name and email are given", async () => {
    const res = await POST(
      makeRequest({
        session_id: "s1",
        answers: allIds.slice(0, 14),
        name: "Jane Doe",
        email: "Jane@Example.com",
      }),
    );
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.emailed).toBe(true);

    const row = insert.mock.calls[0][0] as Record<string, unknown>;
    expect(row.email).toBe("jane@example.com");
    expect(row.source).toBe("checklist");
    expect(row.checklist_score).toBe(body.score);
    expect(row.checklist_band).toBe(body.band);
    expect(row.session_id).toBe("s1");
  });

  it("rejects a lead submission with an invalid email", async () => {
    const res = await POST(
      makeRequest({
        session_id: "s1",
        answers: [],
        name: "Jane Doe",
        email: "not-an-email",
      }),
    );
    expect(res.status).toBe(400);
    expect(insert).not.toHaveBeenCalled();
  });

  it("assigns every possible score to exactly one band", () => {
    for (let score = 0; score <= 100; score++) {
      const matches = CHECKLIST.bands.filter((b) => score >= b.min && score <= b.max);
      expect(matches, `score ${score}`).toHaveLength(1);
    }
  });
});
