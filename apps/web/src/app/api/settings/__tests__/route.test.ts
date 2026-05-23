import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getAuthenticatedRequestUser: vi.fn(),
  maybeSingle: vi.fn(),
  upsert: vi.fn(),
  decrypt: vi.fn(),
  encrypt: vi.fn(),
  configured: vi.fn(),
}));

vi.mock("@/lib/api-auth", () => ({
  getAuthenticatedRequestUser: mocks.getAuthenticatedRequestUser,
  getAdminClient: () => ({
    from: () => ({
      select: () => ({
        eq: () => ({
          maybeSingle: mocks.maybeSingle,
        }),
      }),
      upsert: mocks.upsert,
    }),
  }),
  unauthorized: () => Response.json({ error: "Not authenticated" }, { status: 401 }),
}));

vi.mock("@/lib/settings-crypto", () => ({
  decryptSettingsSecret: mocks.decrypt,
  encryptSettingsSecret: mocks.encrypt,
  settingsCryptoConfigured: mocks.configured,
}));

import { GET, PUT } from "@/app/api/settings/route";

function request(body?: unknown) {
  return new Request("http://localhost/api/settings", {
    method: body === undefined ? "GET" : "PUT",
    headers: { "Content-Type": "application/json", Authorization: "Bearer token" },
    body: body === undefined ? undefined : JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

describe("/api/settings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getAuthenticatedRequestUser.mockResolvedValue({ userId: "user-1", email: "user@example.com" });
    mocks.maybeSingle.mockResolvedValue({
      data: {
        payload_plain: { DEEPSEC_AGENT: "codex" },
        payload_secret_ciphertext: "ct",
        payload_secret_iv: "iv",
        payload_secret_tag: "tag",
        updated_at: "2026-05-23T00:00:00Z",
      },
      error: null,
    });
    mocks.decrypt.mockReturnValue({ AI_GATEWAY_API_KEY: "vck_test_secret" });
    mocks.encrypt.mockReturnValue({ ciphertext: "new-ct", iv: "new-iv", tag: "new-tag" });
    mocks.configured.mockReturnValue(true);
    mocks.upsert.mockResolvedValue({ error: null });
  });

  it("returns plain settings and secret status without returning secret values", async () => {
    const res = await GET(request());
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.plain).toEqual({ DEEPSEC_AGENT: "codex" });
    expect(body.secrets).toEqual({
      AI_GATEWAY_API_KEY: { isSet: true, length: "vck_test_secret".length },
    });
    expect(JSON.stringify(body)).not.toContain("vck_test_secret");
  });

  it("merges plain settings and encrypts updated secrets", async () => {
    const res = await PUT(request({
      plain: { DEEPSEC_AGENT: "claude" },
      secrets: { AI_GATEWAY_API_KEY: "vck_new" },
    }));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(mocks.encrypt).toHaveBeenCalledWith({ AI_GATEWAY_API_KEY: "vck_new" });
    expect(mocks.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        user_id: "user-1",
        payload_plain: { DEEPSEC_AGENT: "claude" },
        payload_secret_ciphertext: "new-ct",
        payload_secret_iv: "new-iv",
        payload_secret_tag: "new-tag",
      }),
      { onConflict: "user_id" },
    );
    expect(body.secrets.AI_GATEWAY_API_KEY).toEqual({ isSet: true, length: 7 });
  });

  it("clears a secret when the value is null", async () => {
    const res = await PUT(request({
      secrets: { AI_GATEWAY_API_KEY: null },
    }));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(mocks.encrypt).not.toHaveBeenCalled();
    expect(mocks.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        payload_secret_ciphertext: null,
        payload_secret_iv: null,
        payload_secret_tag: null,
      }),
      { onConflict: "user_id" },
    );
    expect(body.secrets).toEqual({});
  });

  it("rejects secret updates when encryption is not configured", async () => {
    mocks.configured.mockReturnValue(false);

    const res = await PUT(request({
      secrets: { AI_GATEWAY_API_KEY: "vck_new" },
    }));
    const body = await res.json();

    expect(res.status).toBe(503);
    expect(body.error).toContain("SETTINGS_ENCRYPTION_KEY");
    expect(mocks.upsert).not.toHaveBeenCalled();
  });
});
