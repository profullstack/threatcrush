import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mocks (vi.fn() inside factory — hoisting-safe) ───

vi.mock("@/lib/phone-verification", () => ({
  issuePhoneCode: vi.fn(),
  resolveUserId: vi.fn(),
  CODE_TTL_SECONDS: 600,
}));

import { issuePhoneCode, resolveUserId, CODE_TTL_SECONDS } from "@/lib/phone-verification";

const mockIssuePhoneCode = vi.mocked(issuePhoneCode);
const mockResolveUserId = vi.mocked(resolveUserId);

import { NextRequest } from "next/server";
import { POST } from "@/app/api/auth/send-phone-code/route";

function makeRequest(body: unknown, headers?: Record<string, string>) {
  // A real NextRequest, not a cast Request: the route reads req.cookies for the
  // signup grant, which a plain Request does not have.
  return new NextRequest("http://localhost/api/auth/send-phone-code", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("POST /api/auth/send-phone-code", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockResolveUserId.mockResolvedValue("user-123");
    mockIssuePhoneCode.mockResolvedValue({ phone: "+1234567890" });
  });

  it("sends OTP to valid phone number", async () => {
    const req = makeRequest({ phone: "+1234567890" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.expires_in).toBe(600);
    expect(mockResolveUserId).toHaveBeenCalled();
    expect(mockIssuePhoneCode).toHaveBeenCalledWith({
      userId: "user-123",
      phone: "+1234567890",
    });
  });

  it("rejects missing phone", async () => {
    const req = makeRequest({});
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("required");
  });

  it("rejects when user cannot be identified", async () => {
    mockResolveUserId.mockResolvedValue(null);

    const req = makeRequest({ phone: "+1234567890" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.error).toContain("Could not identify");
  });

  it("handles SMS send failure", async () => {
    const err = new Error("Invalid phone number format");
    (err as Error & { status?: number }).status = 400;
    mockIssuePhoneCode.mockRejectedValue(err);

    const req = makeRequest({ phone: "+1234567890" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("Invalid phone number");
  });

  it("handles internal error", async () => {
    mockIssuePhoneCode.mockRejectedValue(new Error("Network failure"));

    const req = makeRequest({ phone: "+1234567890" });
    const res = await POST(req);
    const body = await res.json();

    // Non-status errors default to 502 (Bad Gateway)
    expect(res.status).toBe(502);
    expect(body.error).toBe("Network failure");
  });
});
