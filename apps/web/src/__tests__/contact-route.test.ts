import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// The guard reads its secret when lib/contact.ts loads.
process.env.FORM_GUARD_SECRET = "test-form-guard-secret-0123456789abcdef";
process.env.RESEND_API_KEY = "re_test";

const insert = vi.fn();
vi.mock("@supabase/supabase-js", () => ({
  createClient: () => ({
    from: () => ({
      insert: (row: unknown) => {
        insert(row);
        return { select: () => ({ single: async () => ({ data: { id: "req_1" }, error: null }) }) };
      },
    }),
  }),
}));

type Contact = typeof import("@/lib/contact");
let mod: Contact;
let POST: (req: Request) => Promise<Response>;

beforeAll(async () => {
  mod = await import("@/lib/contact");
  POST = (await import("@/app/api/contact/route")).POST;
});

beforeEach(() => {
  insert.mockClear();
  vi.mocked(fetch).mockReset();
  vi.mocked(fetch).mockResolvedValue(
    new Response(JSON.stringify({ id: "msg_1" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  );
});

const post = (body: Record<string, unknown>, ip: string) =>
  POST(
    new Request("https://threatcrush.com/api/contact", {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": ip },
      body: JSON.stringify(body),
    }),
  );

const inquiry = {
  name: "Test Person",
  email: "Test@Example.org",
  company: "Acme",
  target: "https://github.com/acme/app",
  stack: "Node",
  timeline: "",
  message: "Please scope a review of our payments service before an audit.",
  topic: "hire",
};

describe("POST /api/contact", () => {
  it("answers a tokenless post like a success and delivers nothing", async () => {
    const res = await post(inquiry, "198.51.100.1");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true });
    expect(insert).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("stores and emails a post carrying a token minted at render", async () => {
    const token = await mod.contact.guard!.issue(Date.now() - 10_000);
    const res = await post({ ...inquiry, fg_token: token, website: "" }, "198.51.100.2");
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ success: true, id: "req_1" });
    expect(insert).toHaveBeenCalledWith({
      name: "Test Person",
      email: "test@example.org",
      company: "Acme",
      message:
        "Please scope a review of our payments service before an audit.\n\n---\nApp or repo: https://github.com/acme/app\nStack: Node",
      topic: "hire",
    });
    const [url, init] = vi.mocked(fetch).mock.calls[0];
    expect(String(url)).toBe("https://api.resend.com/emails");
    const mail = JSON.parse(String((init as RequestInit).body));
    expect(mail.to).toBe("hello@threatcrush.com");
    expect(mail.subject).toContain("[ThreatCrush] New hire inquiry from Test Person");
  });

  it("drops a filled honeypot even with a valid token", async () => {
    const token = await mod.contact.guard!.issue(Date.now() - 10_000);
    const res = await post({ ...inquiry, fg_token: token, website: "spam" }, "198.51.100.3");
    expect(await res.json()).toEqual({ success: true });
    expect(insert).not.toHaveBeenCalled();
  });
});
